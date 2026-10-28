// An npm package from tests/functions/package.json, for tests/e2e/test_functions_e2e.py.
import ms from "ms";

export function handler() {
  return { ms: ms("2 days"), path: import.meta.resolve("ms") };
}
