// GraphQL over the public schema (PostGraphile), reached through core at /graphql/v1.
// Every request runs as the caller's role with their claims, so row level security applies exactly
// as for /rest/v1. Tokens are verified here with the gateway's rules (core auth.rs) rather than
// trusted from headers: anything on the network could otherwise impersonate a user.
import { createServer } from "node:http";
import { createLocalJWKSet, jwtVerify } from "jose";
import { postgraphile } from "postgraphile";
import { makePgService } from "postgraphile/adaptors/pg";
import { grafserv } from "postgraphile/grafserv/node";
import { PostGraphileAmberPreset } from "postgraphile/presets/amber";

const API_KEY_ROLES = ["anon", "service_role"];
const REQUEST_ROLES = ["anon", "authenticated", "service_role"];
const PLACEHOLDER = "change-me";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value || value.includes(PLACEHOLDER)) {
    console.error(JSON.stringify({ ts: Date.now() / 1000, level: "error", service: "graphql",
      msg: `${name} is missing or uses the example value; run \`kilnbase init\`` }));
    process.exit(1);
  }
  return value;
}

const jwks = createLocalJWKSet(JSON.parse(required("KILNBASE_JWKS")));
const databaseUrl = required("DATABASE_URL");
const port = Number(process.env.KILNBASE_GRAPHQL_PORT ?? 4000);

class Unauthorized extends Error {}

async function verify(token, roles) {
  try {
    // The algorithm is ours, never the token header's.
    const { payload } = await jwtVerify(token, jwks, {
      algorithms: ["ES256"], clockTolerance: 30, requiredClaims: ["exp"],
    });
    if (!roles.includes(payload.role)) throw new Unauthorized("invalid token");
    return payload;
  } catch {
    throw new Unauthorized("invalid token");
  }
}

/** The bearer token's claims if there is one, else the API key's (same as the gateway). */
async function caller(headers) {
  const apiKey = headers["apikey"];
  if (!apiKey) throw new Unauthorized("missing apikey");
  const claims = await verify(apiKey, API_KEY_ROLES).catch(() => {
    throw new Unauthorized("invalid apikey");
  });
  const auth = headers["authorization"];
  if (auth === undefined) return claims;
  if (!auth.startsWith("Bearer ")) throw new Unauthorized("authorization header must be a bearer token");
  return verify(auth.slice("Bearer ".length), REQUEST_ROLES);
}

const preset = {
  extends: [PostGraphileAmberPreset],
  pgServices: [makePgService({
    connectionString: databaseUrl,
    schemas: ["public"],
    // The schema lists what a signed-in user may reach, so tables hidden from /rest/v1 by the RLS
    // rule (migrations/0003) stay out of it too; otherwise service_role's grants would publish them.
    pgSettingsForIntrospection: { role: "authenticated" },
  })],
  grafserv: { port, graphqlPath: "/", graphiql: false, watch: false, maxRequestLength: 100_000 },
  grafast: {
    explain: false,
    context(requestContext) {
      const claims = requestContext.node?.req?.kilnbaseClaims;
      return {
        pgSettings: {
          role: claims.role,
          "request.jwt.claims": JSON.stringify(claims),
          statement_timeout: "10s",
        },
      };
    },
  },
};

const pgl = postgraphile(preset);
const serv = pgl.createServ(grafserv);
const handler = serv.createHandler();

function send(res, status, body) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const server = createServer(async (req, res) => {
  if (req.url === "/health") return send(res, 200, { status: "ok" });
  if (req.url !== "/" && !req.url.startsWith("/?")) {
    return send(res, 404, { code: "not_found", message: "not found" });
  }
  try {
    req.kilnbaseClaims = await caller(req.headers);
  } catch (e) {
    if (e instanceof Unauthorized) return send(res, 401, { code: "unauthorized", message: e.message });
    throw e;
  }
  handler(req, res);
});

server.listen(port, () => {
  console.error(JSON.stringify({ ts: Date.now() / 1000, level: "info", service: "graphql",
    msg: `listening on ${port}` }));
});
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => pgl.release().then(() => process.exit(0))));
}
