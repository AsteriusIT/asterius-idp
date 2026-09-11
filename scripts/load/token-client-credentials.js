// Token endpoint under load: `client_credentials`, `private_key_jwt`, DPoP.
//
// The busiest endpoint of a FAPI 2.0 deployment (FAPI 2.0 SP §6.1: short
// access tokens bring every client back here often), measured on the grant
// that isolates it — no browser, no code, no user — so that what is timed is
// the endpoint itself: two signature verifications (assertion, proof), two
// replay inserts, the client read, the token signature and the audit write.
//
//     k6 run --vus 32 --duration 60s scripts/load/token-client-credentials.js
//
// Each VU is one client instance with its own DPoP key; every request carries
// a fresh assertion and a fresh proof. See README.md for the stack to run it
// against and the environment it reads.

import { check } from 'k6';
import { Trend } from 'k6/metrics';
import { clientCredentials, configFromEnv, generateDpopKey, importClientKey } from './lib.js';

const keyDer = open(__ENV.CLIENT_KEY || `${__ENV.LOAD_DIR || '.'}/client-key.der`, 'b');

export const options = {
  thresholds: {
    // A refused request is a set-up problem (replay, clock, audience), not a
    // measurement: abort early rather than time 401s.
    checks: [{ threshold: 'rate>0.99', abortOnFail: true, delayAbortEval: '5s' }],
    http_req_duration: ['p(95)<500'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const tokenLatency = new Trend('token_endpoint_duration', true);

let cfg;
let dpop;

export default async function () {
  if (!cfg) {
    cfg = configFromEnv(await importClientKey(keyDer));
    dpop = await generateDpopKey();
  }
  const response = await clientCredentials(cfg, dpop, __ENV.SCOPE || 'load.read', { name: 'token' });
  tokenLatency.add(response.timings.duration);
  check(response, {
    'token issued (200)': (r) => r.status === 200,
    'token is DPoP-bound': (r) => r.status === 200 && r.json('token_type') === 'DPoP',
  }) || console.error(`${response.status} ${response.body}`);
}
