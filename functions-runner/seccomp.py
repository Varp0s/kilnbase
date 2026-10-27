"""Writes seccomp.json: Docker's default profile plus what nsjail needs to build its sandboxes.

Docker only allows the namespace and mount syscalls to containers with CAP_SYS_ADMIN; the functions
container has no capabilities, so they are added unconditionally here. Each jail then forbids them
again for the function itself (src/kilnbase_functions/policy.kafel).

Run after bumping the pinned profile: uv run python functions-runner/seccomp.py
"""

import hashlib
import json
import urllib.request
from pathlib import Path

VERSION = "seccomp/v0.2.4"  # github.com/moby/profiles
SHA256 = "785b2429264afba4d594320337cb17f144f3c7d51585f9805eef72e28f4f9334"
URL = f"https://raw.githubusercontent.com/moby/profiles/{VERSION}/seccomp/default.json"
NSJAIL = [
    "clone", "unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
    "sethostname", "setdomainname",
]  # fmt: skip


def main() -> None:
    with urllib.request.urlopen(URL, timeout=30) as res:  # noqa: S310 - fixed https URL
        raw = res.read()
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit(f"{URL} does not match the pinned checksum")
    profile = json.loads(raw)
    profile["syscalls"].append(
        {
            "names": NSJAIL,
            "action": "SCMP_ACT_ALLOW",
            "comment": f"kilnbase: nsjail sandboxes (Docker {VERSION} + these)",
        }
    )
    out = Path(__file__).with_name("seccomp.json")
    out.write_text(json.dumps(profile, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
