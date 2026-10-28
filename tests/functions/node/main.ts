// TypeScript functions for tests/e2e/test_functions_e2e.py; ?what= picks a behaviour.
import { readdirSync, writeFileSync } from "node:fs";

interface Request {
  method: string;
  query: Record<string, string>;
  body: Uint8Array;
  user: { role: string; sub?: string };
}

export async function handler(request: Request) {
  console.log("noise on stdout {not json"); // must not corrupt the response
  switch (request.query.what) {
    case "env":
      return process.env;
    case "files": {
      let writable = true;
      try {
        writeFileSync("/etc/kilnbase-test", "x");
      } catch {
        writable = false;
      }
      return { root_writable: writable, functions: readdirSync("/functions"), cwd: readdirSync(".") };
    }
    case "memory": {
      const chunks: Uint8Array[] = [];
      for (;;) chunks.push(new Uint8Array(64 * 1024 * 1024).fill(1));
    }
    case "heap": {
      const arrays: number[][] = [];
      for (;;) arrays.push(new Array(1_000_000).fill(1.5)); // 8 MB each, on the JS heap
    }
    case "loop":
      for (;;);
    case "throw":
      throw new Error("boom");
    case "bytes":
      setInterval(() => {}, 1000); // left running: the call must still return at once
      return new Uint8Array([0, 1, 2]);
    default:
      return new Response(
        JSON.stringify({
          role: request.user.role,
          sub: request.user.sub ?? null,
          echo: new TextDecoder().decode(request.body),
        }),
        { status: 201, headers: { "content-type": "application/json", "x-runtime": "node" } },
      );
  }
}
