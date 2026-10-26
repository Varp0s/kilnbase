import { type Result, isError, ok, request, toError } from "./http.js";

type Headers = () => Promise<Record<string, string>>;

export interface StoredObject {
  id: string;
  bucket: string;
  name: string;
  size: number;
  mime_type: string;
}

export interface UploadOptions {
  contentType?: string;
  /** Replace an existing object instead of failing with `already_exists`. */
  upsert?: boolean;
}

/** Needs the server's optional image service; non-images are rejected. */
export interface TransformOptions {
  /** 1-2500 pixels; leave one out to keep the aspect ratio. */
  width?: number;
  height?: number;
  resize?: "cover" | "contain" | "fill";
  /** 1-100. */
  quality?: number;
  format?: "origin" | "webp" | "avif" | "jpeg" | "png";
}

const transformQuery = (t: TransformOptions) =>
  new URLSearchParams(Object.entries(t).flatMap(([k, v]) => (v === undefined ? [] : [[k, String(v)]]))).toString();

/** Encodes each path segment but keeps `/` separators. */
export const encodePath = (path: string) => path.split("/").map(encodeURIComponent).join("/");

export class BucketClient {
  constructor(
    private readonly url: string,
    private readonly bucket: string,
    private readonly headers: Headers,
  ) {}

  async upload(
    path: string,
    body: Blob | ArrayBuffer | Uint8Array | string | ReadableStream,
    { contentType, upsert = false }: UploadOptions = {},
  ): Promise<Result<StoredObject>> {
    const headers = await this.headers();
    const type = contentType ?? (body instanceof Blob && body.type ? body.type : undefined);
    if (type) headers["Content-Type"] = type;
    const init: RequestInit & { duplex?: "half" } = {
      method: upsert ? "PUT" : "POST",
      headers,
      body: body as BodyInit,
    };
    if (body instanceof ReadableStream) init.duplex = "half";
    const res = await request(this.#objectUrl(path), init);
    if (isError(res)) return { data: null, error: res };
    return res.ok ? ok((await res.json()) as StoredObject) : toError(res);
  }

  /** With `transform`, returns a resized/converted image instead of the stored bytes. */
  async download(path: string, { transform }: { transform?: TransformOptions } = {}): Promise<Result<Blob>> {
    const url = transform
      ? `${this.url}/storage/v1/render/image/authenticated/${this.bucket}/${encodePath(path)}?${transformQuery(transform)}`
      : this.#objectUrl(path);
    const res = await request(url, { headers: await this.headers() });
    if (isError(res)) return { data: null, error: res };
    return res.ok ? ok(await res.blob()) : toError(res);
  }

  async remove(path: string): Promise<Result<null>> {
    const res = await request(this.#objectUrl(path), {
      method: "DELETE",
      headers: await this.headers(),
    });
    if (isError(res)) return { data: null, error: res };
    return res.ok ? ok(null) : toError(res);
  }

  /** A link anyone can open until it expires; only the object's readers may create one. */
  async createSignedUrl(path: string, expiresIn: number): Promise<Result<{ signedUrl: string; expiresAt: number }>> {
    const headers = { ...(await this.headers()), "Content-Type": "application/json" };
    const res = await request(`${this.url}/storage/v1/object/sign/${this.bucket}/${encodePath(path)}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ expires_in: expiresIn }),
    });
    if (isError(res)) return { data: null, error: res };
    if (!res.ok) return toError(res);
    const body = (await res.json()) as { signed_url: string; expires_at: number };
    return ok({ signedUrl: `${this.url}${body.signed_url}`, expiresAt: body.expires_at });
  }

  /** URL of an object in a public bucket; no request is made. */
  getPublicUrl(path: string, { transform }: { transform?: TransformOptions } = {}): string {
    if (transform) {
      return `${this.url}/storage/v1/render/image/public/${this.bucket}/${encodePath(path)}?${transformQuery(transform)}`;
    }
    return `${this.url}/storage/v1/object/public/${this.bucket}/${encodePath(path)}`;
  }

  #objectUrl(path: string): string {
    return `${this.url}/storage/v1/object/${this.bucket}/${encodePath(path)}`;
  }
}

export class StorageClient {
  constructor(
    private readonly url: string,
    private readonly headers: Headers,
  ) {}

  from(bucket: string): BucketClient {
    return new BucketClient(this.url, encodeURIComponent(bucket), this.headers);
  }
}
