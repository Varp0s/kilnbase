// Runs inside the jail with Node, for functions written in TypeScript: the request arrives as JSON on
// stdin and the response leaves on the file descriptor named in argv[2], so console.log() output
// cannot corrupt it.

import { closeSync, readFileSync, writeSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

async function encode(result) {
  if (result instanceof Response) {
    const data = Buffer.from(await result.arrayBuffer());
    const headers = Object.fromEntries(result.headers);
    return { status: result.status, headers, body_base64: data.toString("base64") };
  }
  let contentType;
  let data;
  if (result instanceof Uint8Array) {
    [contentType, data] = ["application/octet-stream", Buffer.from(result)];
  } else if (typeof result === "string") {
    [contentType, data] = ["text/plain; charset=utf-8", Buffer.from(result)];
  } else {
    [contentType, data] = ["application/json", Buffer.from(JSON.stringify(result ?? null))];
  }
  return { status: 200, headers: { "content-type": contentType }, body_base64: data.toString("base64") };
}

const out = Number(process.argv[2]);
const request = JSON.parse(readFileSync(0, "utf8"));
request.body = Buffer.from(request.body_base64, "base64");
delete request.body_base64;
const { handler } = await import(pathToFileURL(join(process.cwd(), "main.ts")).href);
writeSync(out, JSON.stringify(await encode(await handler(request))));
closeSync(out);
// Sockets or timers the function left open must not hold the call until the time limit.
process.exit(0);
