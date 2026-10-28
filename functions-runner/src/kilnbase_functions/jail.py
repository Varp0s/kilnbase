import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .config import Config

HERE = Path(__file__).parent
POLICY = (HERE / "policy.kafel").read_text()
BOOTSTRAP = HERE / "bootstrap.py"
NODE_BOOTSTRAP = HERE / "bootstrap.mjs"
# V8 reserves about 1.2 GB of address space at start (most of it never touched), so a TypeScript
# function's address-space limit is this plus its memory budget.
NODE_RESERVED_MB = 1280
RESPONSE_LIMIT = 6 * 1024 * 1024  # base64 of a 4 MiB body plus headers
LOG_LIMIT = 16 * 1024
JAIL_TMP = "/tmp"  # noqa: S108 - a private tmpfs inside each jail
MOUNT = "/mnt"  # exists in the read-only root; the function's directory is bound here
DEPS_MOUNT = "/opt"  # likewise for the packages from functions/requirements.txt


SECRET_LINE = re.compile(r"(\*|[a-z0-9_-]{1,63})\.([A-Z_][A-Z0-9_]*)=(.*)")


def secrets(functions_dir: Path, name: str) -> dict[str, str]:
    """
    functions/.secrets lines `<function>.<KEY>=value` (or `*.<KEY>=value` for all functions).
    Read on every call, so edits apply without a restart. The file is never visible inside a
    jail (the functions directory is hidden there); each function gets only its own entries.
    """
    path = functions_dir / ".secrets"
    if not path.is_file():
        return {}
    shared, own = {}, {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = SECRET_LINE.fullmatch(line.strip())
        if match:
            scope, key, value = match.groups()
            if scope == "*":
                shared[key] = value
            elif scope == name:
                own[key] = value
    return shared | own


@dataclass
class Outcome:
    status: int  # nsjail's exit status
    response: bytes  # JSON from bootstrap.py, empty if it never answered
    output: str  # what the function printed, truncated
    timed_out: bool = False
    too_large: bool = False


def argv(config: Config, function_dir: Path, response_fd: int) -> list[str]:
    """
    One throwaway jail per call: own user, PID, mount, IPC and UTS namespaces; the root filesystem
    read-only with other functions hidden; resource limits; the syscall filter in policy.kafel.
    The network namespace is shared so functions can reach the gateway and the internet, which
    is why the compose network gives this container no route to the database or internal services.
    Nothing from this service's environment is passed in, only the variables listed here and the
    function's own entries from functions/.secrets. A `main.ts` runs on Node, a `main.py` on Python.
    """
    # Secrets first, so they can never replace the variables below.
    env = secrets(config.functions_dir, function_dir.name) | {
        "KILNBASE_URL": config.gateway_url,
        "KILNBASE_ANON_KEY": config.anon_key,
        "HOME": JAIL_TMP,
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    if (function_dir / "main.ts").is_file():
        memory_mb = NODE_RESERVED_MB + config.memory_mb
        command = [
            "/usr/local/bin/node", "--disable-warning=ExperimentalWarning",
            f"--max-old-space-size={config.memory_mb}", str(NODE_BOOTSTRAP), str(response_fd),
        ]  # fmt: skip
    else:
        memory_mb = config.memory_mb
        command = [
            "/usr/local/bin/python3", "-I", "-B", str(BOOTSTRAP), str(response_fd),
            *([DEPS_MOUNT] if config.deps_dir else []),
        ]  # fmt: skip
    return [
        "nsjail", "-Mo", "-Q",
        "--chroot", "/",
        "--user", "65534", "--group", "65534",
        "--hostname", "function",
        "--disable_proc",
        "--disable_clone_newnet",
        "--tmpfsmount", JAIL_TMP,
        "--tmpfsmount", str(config.functions_dir),
        *(["--tmpfsmount", str(config.deps_dir.parent)] if config.deps_dir else []),
        *(["--bindmount_ro", f"{config.deps_dir}:{DEPS_MOUNT}"] if config.deps_dir else []),
        "--bindmount_ro", f"{function_dir}:{MOUNT}",
        "--cwd", MOUNT,
        "--time_limit", str(config.timeout),
        "--rlimit_cpu", str(config.timeout),
        "--rlimit_as", str(memory_mb),
        "--rlimit_nproc", "64",
        "--rlimit_fsize", "16",
        "--rlimit_nofile", "128",
        "--seccomp_string", POLICY,
        "--pass_fd", str(response_fd),
        *(arg for k, v in env.items() for arg in ("--env", f"{k}={v}")),
        "--",
        *command,
    ]  # fmt: skip


async def _read(reader: asyncio.StreamReader, limit: int, kill_on_overflow) -> tuple[bytes, bool]:
    data = bytearray()
    over = False
    while chunk := await reader.read(65536):
        if len(data) + len(chunk) > limit:
            over = True
            if kill_on_overflow:
                kill_on_overflow()
                break
            continue  # keep draining so the function never blocks on a full pipe
        data += chunk
    return bytes(data), over


async def run(config: Config, function_dir: Path, request: bytes) -> Outcome:
    loop = asyncio.get_running_loop()
    read_fd, write_fd = os.pipe()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv(config, function_dir, write_fd),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            pass_fds=(write_fd,),
        )
    except BaseException:
        os.close(read_fd)
        raise
    finally:
        os.close(write_fd)
    response_reader = asyncio.StreamReader()
    transport, _ = await loop.connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(response_reader), os.fdopen(read_fd, "rb", 0)
    )

    def kill() -> None:
        if proc.returncode is None:
            proc.kill()

    async def feed() -> None:
        try:
            proc.stdin.write(request)
            await proc.stdin.drain()
            proc.stdin.close()
        except BrokenPipeError, ConnectionResetError:
            pass  # the function exited without reading its input

    try:
        (response, too_large), (output, _), _, _ = await asyncio.wait_for(
            asyncio.gather(
                _read(response_reader, RESPONSE_LIMIT, kill),
                _read(proc.stdout, LOG_LIMIT, None),
                feed(),
                proc.wait(),
            ),
            # nsjail enforces the limit; this only guards against nsjail itself hanging.
            timeout=config.timeout + 5,
        )
    except TimeoutError:
        kill()
        await proc.wait()
        return Outcome(proc.returncode, b"", "", timed_out=True)
    finally:
        transport.close()
    text = output.decode(errors="replace")
    # nsjail kills at --time_limit with SIGKILL, which it reports as 128 + 9.
    timed_out = proc.returncode == 137 and not response and not too_large
    return Outcome(proc.returncode, response, text, timed_out=timed_out, too_large=too_large)
