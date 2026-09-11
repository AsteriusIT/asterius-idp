// SSF delivery under load: a receiver polling its stream (RFC 8936).
//
//     k6 run --vus 8 --duration 30s scripts/load/ssf-poll.js
//
// What this measures is the cost of a receiver that polls as fast as it can —
// the denial-of-service shape of §2.1, where `returnImmediately: true` turns
// long-polling into a tight loop — with an empty or near-empty queue. Push
// delivery (RFC 8935) is driven by the outbox worker, not by a client, so it
// is not a load-tool scenario: its database side is in explain.sh (the outbox
// claim and the poll queue), and its wall-clock side is the receiver's.
//
// Requires `features.ssf = true` and a client registered for `ssf.manage` and
// `ssf.poll` with the transmitter's endpoints on its resource allow-list
// (seed.sql registers `load-receiver` that way). Each VU obtains its
// own DPoP-bound tokens; the first VU to arrive creates the stream, the others
// find it already there.

import { check } from 'k6';
import http from 'k6/http';
import { Trend } from 'k6/metrics';
import { clientCredentials, configFromEnv, dpopProof, generateDpopKey, importClientKey, urlPath } from './lib.js';

const keyDer = open(__ENV.CLIENT_KEY || `${__ENV.LOAD_DIR || '.'}/client-key.der`, 'b');

export const options = {
  thresholds: {
    checks: [{ threshold: 'rate>0.99', abortOnFail: true, delayAbortEval: '5s' }],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

const pollLatency = new Trend('ssf_poll_duration', true);

let cfg;
let dpop;
let pollToken;
let pollUrl;

async function proved(accessToken, method, url, body, name) {
  const proof = await dpopProof(dpop, method, url, accessToken);
  return http.request(method, cfg.base + urlPath(url), body, {
    headers: {
      Host: cfg.host,
      Authorization: `DPoP ${accessToken}`,
      DPoP: proof,
      'Content-Type': 'application/json',
    },
    tags: { name },
  });
}

// A token audienced at one of the transmitter's own APIs: the stream
// configuration endpoint for `ssf.manage`, the poll endpoint for `ssf.poll`
// (SSF 1.0 §8; RFC 8707). Two tokens, because each API accepts only its own.
async function tokenFor(resource, scope) {
  const issued = await clientCredentials(cfg, dpop, scope, { name: 'token' }, resource);
  if (!check(issued, { [`${scope} token issued (200)`]: (r) => r.status === 200 })) {
    console.error(`token ${issued.status} ${issued.body}`);
    return null;
  }
  return issued.json('access_token');
}

// The receiver's stream: created by the first VU to ask, found by the rest.
async function streamId(manageToken) {
  const streams = `${cfg.issuer}/ssf/streams`;
  const created = await proved(
    manageToken,
    'POST',
    streams,
    JSON.stringify({ delivery: { method: 'urn:ietf:rfc:8936' } }),
    'create-stream',
  );
  if (created.status === 201) {
    return created.json('stream_id');
  }
  const listed = await proved(manageToken, 'GET', streams, null, 'list-streams');
  if (!check(listed, { 'stream exists': (r) => r.status === 200 && r.json('0.stream_id') })) {
    console.error(`stream ${created.status} ${created.body} / ${listed.status} ${listed.body}`);
    return null;
  }
  return listed.json('0.stream_id');
}

export default async function () {
  if (!cfg) {
    cfg = configFromEnv(await importClientKey(keyDer));
    cfg.clientId = __ENV.CLIENT_ID || 'load-receiver';
    dpop = await generateDpopKey();
    const manageToken = await tokenFor(`${cfg.issuer}/ssf/streams`, 'ssf.manage');
    if (!manageToken) {
      return;
    }
    const id = await streamId(manageToken);
    if (!id) {
      return;
    }
    pollUrl = `${cfg.issuer}/ssf/poll/${id}`;
    pollToken = await tokenFor(`${cfg.issuer}/ssf/poll`, 'ssf.poll');
    if (!pollToken) {
      return;
    }
  }
  if (!pollToken) {
    return;
  }
  const polled = await proved(
    pollToken,
    'POST',
    pollUrl,
    JSON.stringify({ maxEvents: 64, returnImmediately: true }),
    'poll',
  );
  pollLatency.add(polled.timings.duration);
  check(polled, { 'poll answered (200)': (r) => r.status === 200 }) ||
    console.error(`poll ${polled.status} ${polled.body}`);
}
