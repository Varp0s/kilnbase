// Gateway overhead: the same PostgREST query through the Rust gateway and directly.
// Run with scripts/bench.sh, which joins the compose network and passes the keys.
import http from "k6/http";
import { check } from "k6";

const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || "20s";

export const options = {
  scenarios: {
    direct: { executor: "constant-vus", vus: VUS, duration: DURATION, exec: "direct" },
    gateway: { executor: "constant-vus", vus: VUS, duration: DURATION, exec: "gateway", startTime: "25s" },
    auth_user: { executor: "constant-vus", vus: VUS, duration: DURATION, exec: "gatewayUser", startTime: "50s" },
  },
  // Thresholds make k6 print per-target latency; the limits are deliberately loose.
  thresholds: {
    "http_req_duration{target:direct}": ["p(99)<1000"],
    "http_req_duration{target:gateway}": ["p(99)<1000"],
    "http_req_duration{target:gateway_user}": ["p(99)<1000"],
    checks: ["rate>0.999"],
  },
  summaryTrendStats: ["avg", "med", "p(95)", "p(99)", "max"],
};

const ANON = __ENV.ANON_KEY;
const USER = __ENV.USER_TOKEN;
const QUERY = "bench_items?select=id,name&order=id&limit=10";

export function direct() {
  const r = http.get(`http://postgrest:3000/${QUERY}`, {
    headers: { Authorization: `Bearer ${ANON}` },
    tags: { target: "direct" },
  });
  check(r, { ok: (res) => res.status === 200 });
}

export function gateway() {
  const r = http.get(`http://core:8000/rest/v1/${QUERY}`, {
    headers: { apikey: ANON },
    tags: { target: "gateway" },
  });
  check(r, { ok: (res) => res.status === 200 });
}

export function gatewayUser() {
  const r = http.get(`http://core:8000/rest/v1/${QUERY}`, {
    headers: { apikey: ANON, Authorization: `Bearer ${USER}` },
    tags: { target: "gateway_user" },
  });
  check(r, { ok: (res) => res.status === 200 });
}
