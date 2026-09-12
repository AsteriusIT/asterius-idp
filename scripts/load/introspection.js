// Introspection endpoint under load: RFC 7662, `private_key_jwt` (`ast-1sk.1`).
//
// The endpoint a resource server calls once per API request it cannot verify
// locally, so its cost is multiplied by somebody else's traffic rather than by
// this server's. What is timed per request is: one assertion verification and
// one replay insert (§2.1's client authentication), the access token's own
// signature verification, and then four reads that happen whatever the answer
// — the `jti` denylist, the revocation cutoffs, the grant, and the tenant's
// resource-server registry.
//
// That last point is the reason this script exists rather than a note saying
// "like /revoke but read-only". The endpoint deliberately does the same work
// for an authorized caller and an unauthorized one (RFC 7662 §4: no oracle),
// so the *refused* case is not the cheap case, and a deployment sizing this
// endpoint cannot assume that rejected traffic is free.
//
//     k6 run --vus 32 --duration 60s scripts/load/introspection.js
//
// Each VU mints one access token with `client_credentials` and then
// introspects it repeatedly, which is the shape of the real traffic: a token
// is minted once and asked about many times.
//
// Written to be run, not to be believed: no number here is a threshold this
// repository asserts, and `ast-p2l.8`'s README says what stack to run it
// against. The check thresholds only catch a misconfigured run.

import { check } from 'k6';
import { Trend } from 'k6/metrics';
import http from 'k6/http';
import {
  CLIENT_ASSERTION_TYPE,
  clientAssertion,
  clientCredentials,
  configFromEnv,
  generateDpopKey,
  importClientKey,
  urlPath,
} from './lib.js';

const keyDer = open(__ENV.CLIENT_KEY || `${__ENV.LOAD_DIR || '.'}/client-key.der`, 'b');

export const options = {
  thresholds: {
    checks: [{ threshold: 'rate>0.99', abortOnFail: true, delayAbortEval: '5s' }],
    http_req_duration: ['p(95)<500'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const introspectionLatency = new Trend('introspection_endpoint_duration', true);

let cfg;
let dpop;
let accessToken;

// One introspection request. `token` is whatever is being asked about: the
// caller's own token, or — with `SCAN=1` — a value nothing ever issued, which
// is the path RFC 7662 §4's attacker takes and which must not be faster.
async function introspect(token, tags) {
  const url = `${cfg.issuer}/introspect`;
  const assertion = await clientAssertion(cfg.clientId, cfg.issuer, cfg.kid, cfg.clientKey);
  return http.post(
    cfg.base + urlPath(url),
    {
      token,
      token_type_hint: 'access_token',
      client_id: cfg.clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: assertion,
    },
    { headers: { Host: cfg.host }, tags },
  );
}

export default async function () {
  if (!cfg) {
    cfg = configFromEnv(await importClientKey(keyDer));
    dpop = await generateDpopKey();
  }
  if (!accessToken) {
    const minted = await clientCredentials(cfg, dpop, __ENV.SCOPE || 'load.read', { name: 'token' });
    if (minted.status !== 200) {
      console.error(`could not mint a token to introspect: ${minted.status} ${minted.body}`);
      return;
    }
    accessToken = minted.json('access_token');
  }

  // The unknown-value run measures the answer a scan gets. It is a separate
  // run rather than a mixed one, so the two medians are comparable.
  const scanning = __ENV.SCAN === '1';
  const token = scanning ? `not-a-token-${Math.random()}` : accessToken;

  const response = await introspect(token, { name: 'introspect' });
  introspectionLatency.add(response.timings.duration);

  check(response, {
    // §2.2: every answer about a token is a 200, including the ones that say
    // nothing. A 401 here is a set-up problem (assertion, clock, audience).
    'answered (200)': (r) => r.status === 200,
    'active matches what was asked about': (r) =>
      r.status === 200 && r.json('active') === !scanning,
  }) || console.error(`${response.status} ${response.body}`);
}
