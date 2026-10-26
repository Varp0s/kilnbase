import assert from "node:assert/strict";
import { test } from "node:test";

import { Query, listValue } from "../dist/rest.js";
import { BucketClient, encodePath } from "../dist/storage.js";

const noHeaders = async () => ({});

test("builds PostgREST query strings", () => {
  const q = new Query("http://x", "todos", noHeaders)
    .select("id,title")
    .eq("done", false)
    .gte("id", 10)
    .in("tag", ["a", "b,c"])
    .order("id", { ascending: false })
    .range(20, 29);
  const url = new URL(q.toUrl());
  assert.equal(url.pathname, "/rest/v1/todos");
  assert.equal(url.searchParams.get("select"), "id,title");
  assert.equal(url.searchParams.get("done"), "eq.false");
  assert.equal(url.searchParams.get("id"), "gte.10");
  assert.equal(url.searchParams.get("tag"), 'in.(a,"b,c")');
  assert.equal(url.searchParams.get("order"), "id.desc");
  assert.equal(url.searchParams.get("offset"), "20");
  assert.equal(url.searchParams.get("limit"), "10");
});

test("filter values cannot inject extra parameters", () => {
  const url = new URL(new Query("http://x", "t", noHeaders).eq("name", "a&role=eq.admin").toUrl());
  assert.equal(url.searchParams.get("name"), "eq.a&role=eq.admin");
  assert.equal(url.searchParams.get("role"), null);
});

test("quotes list values with reserved characters", () => {
  assert.equal(listValue("plain"), "plain");
  assert.equal(listValue('say "hi"'), '"say \\"hi\\""');
  assert.equal(listValue("a\\b"), '"a\\\\b"');
  assert.equal(listValue(null), "null");
});

test("encodes storage paths per segment", () => {
  assert.equal(encodePath("dir/a b/ğ?.png"), "dir/a%20b/%C4%9F%3F.png");
});

test("public URLs point at the image service only when transforming", () => {
  const bucket = new BucketClient("http://x", "pics", noHeaders);
  assert.equal(bucket.getPublicUrl("a b.png"), "http://x/storage/v1/object/public/pics/a%20b.png");
  assert.equal(
    bucket.getPublicUrl("a b.png", { transform: { width: 200, height: undefined, format: "webp" } }),
    "http://x/storage/v1/render/image/public/pics/a%20b.png?width=200&format=webp",
  );
});
