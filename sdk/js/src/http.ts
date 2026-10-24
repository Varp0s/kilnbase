export interface KilnbaseError {
  code: string;
  message: string;
  status: number;
}

/** Every call resolves to this shape; HTTP failures never throw. */
export type Result<T> = { data: T; error: null } | { data: null; error: KilnbaseError };

export const ok = <T>(data: T): Result<T> => ({ data, error: null });
export const fail = <T = never>(status: number, code: string, message: string): Result<T> => ({
  data: null,
  error: { status, code, message },
});

/** Reads a Kilnbase or PostgREST error body into a uniform error. */
export async function toError<T = never>(res: Response): Promise<Result<T>> {
  let body: Record<string, unknown> = {};
  try {
    body = (await res.json()) as Record<string, unknown>;
  } catch {
    // Non-JSON error body; fall back to the status text.
  }
  const code = String(body.code ?? `http_${res.status}`);
  const message = String(body.message ?? (res.statusText || "request failed"));
  return fail(res.status, code, message);
}

export async function request(input: string, init: RequestInit): Promise<Response | KilnbaseError> {
  try {
    return await fetch(input, init);
  } catch (e) {
    return { status: 0, code: "network_error", message: e instanceof Error ? e.message : String(e) };
  }
}

export const isError = (r: Response | KilnbaseError): r is KilnbaseError => !(r instanceof Response);
