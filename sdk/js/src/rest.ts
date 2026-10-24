import { type Result, isError, ok, request, toError } from "./http.js";

type Primitive = string | number | boolean | null;
type Headers = () => Promise<Record<string, string>>;

/** Quotes a value for PostgREST list syntax when it contains reserved characters. */
export function listValue(v: Primitive): string {
  const s = String(v);
  return /[,()"\\:\s]/.test(s) ? `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"` : s;
}

/**
 * Chainable query against `/rest/v1/<table>`; awaiting it runs the request.
 * Filters map one-to-one onto PostgREST operators.
 */
export class Query<T = Record<string, unknown>> implements PromiseLike<Result<T[]>> {
  #params = new URLSearchParams();
  #method: "GET" | "POST" | "PATCH" | "DELETE" = "GET";
  #body: unknown = undefined;
  #prefer: string[] = [];

  constructor(
    private readonly url: string,
    private readonly table: string,
    private readonly headers: Headers,
  ) {}

  select(columns = "*"): this {
    this.#params.set("select", columns);
    return this;
  }

  insert(rows: Partial<T> | Partial<T>[]): this {
    return this.#write("POST", rows);
  }

  /** Insert, or update rows whose primary key already exists. */
  upsert(rows: Partial<T> | Partial<T>[]): this {
    this.#prefer.push("resolution=merge-duplicates");
    return this.#write("POST", rows);
  }

  update(values: Partial<T>): this {
    return this.#write("PATCH", values);
  }

  delete(): this {
    return this.#write("DELETE", undefined);
  }

  eq(column: string, value: Primitive): this {
    return this.#filter(column, "eq", value);
  }
  neq(column: string, value: Primitive): this {
    return this.#filter(column, "neq", value);
  }
  gt(column: string, value: Primitive): this {
    return this.#filter(column, "gt", value);
  }
  gte(column: string, value: Primitive): this {
    return this.#filter(column, "gte", value);
  }
  lt(column: string, value: Primitive): this {
    return this.#filter(column, "lt", value);
  }
  lte(column: string, value: Primitive): this {
    return this.#filter(column, "lte", value);
  }
  like(column: string, pattern: string): this {
    return this.#filter(column, "like", pattern);
  }
  ilike(column: string, pattern: string): this {
    return this.#filter(column, "ilike", pattern);
  }
  is(column: string, value: null | boolean): this {
    return this.#filter(column, "is", value);
  }
  in(column: string, values: Primitive[]): this {
    this.#params.append(column, `in.(${values.map(listValue).join(",")})`);
    return this;
  }

  order(column: string, { ascending = true }: { ascending?: boolean } = {}): this {
    this.#params.append("order", `${column}.${ascending ? "asc" : "desc"}`);
    return this;
  }

  limit(count: number): this {
    this.#params.set("limit", String(count));
    return this;
  }

  range(from: number, to: number): this {
    this.#params.set("offset", String(from));
    this.#params.set("limit", String(to - from + 1));
    return this;
  }

  /** @internal Exposed for tests. */
  toUrl(): string {
    const qs = this.#params.toString();
    return `${this.url}/rest/v1/${encodeURIComponent(this.table)}${qs ? `?${qs}` : ""}`;
  }

  /** Resolves to exactly one row; an error if zero or several match. */
  async single(): Promise<Result<T>> {
    // With this Accept header PostgREST returns one object instead of an array.
    return (await this.#run({ Accept: "application/vnd.pgrst.object+json" })) as unknown as Result<T>;
  }

  then<R1 = Result<T[]>, R2 = never>(
    onfulfilled?: ((value: Result<T[]>) => R1 | PromiseLike<R1>) | null,
    onrejected?: ((reason: unknown) => R2 | PromiseLike<R2>) | null,
  ): PromiseLike<R1 | R2> {
    return this.#run({}).then(onfulfilled, onrejected);
  }

  #filter(column: string, op: string, value: Primitive): this {
    this.#params.append(column, `${op}.${String(value)}`);
    return this;
  }

  #write(method: "POST" | "PATCH" | "DELETE", body: unknown): this {
    this.#method = method;
    this.#body = body;
    return this;
  }

  async #run(extra: Record<string, string>): Promise<Result<T[]>> {
    const headers: Record<string, string> = { ...(await this.headers()), ...extra };
    if (this.#method !== "GET") {
      // Writes return the affected rows, so callers see exactly what RLS let through.
      headers.Prefer = ["return=representation", ...this.#prefer].join(",");
    }
    if (this.#body !== undefined) headers["Content-Type"] = "application/json";
    const res = await request(this.toUrl(), {
      method: this.#method,
      headers,
      body: this.#body === undefined ? undefined : JSON.stringify(this.#body),
    });
    if (isError(res)) return { data: null, error: res };
    if (!res.ok) return toError(res);
    const text = await res.text();
    return ok((text ? JSON.parse(text) : []) as T[]);
  }
}
