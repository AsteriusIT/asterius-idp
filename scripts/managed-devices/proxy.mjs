#!/usr/bin/env node
// Controlled authenticated edge: no production/live MDM claim.
// The public device leaf is forwarded only after this exact TLS handshake.
import https from 'node:https';
import fs from 'node:fs';
import { pipeline } from 'node:stream';

const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const publicUrl = new URL(config.issuer);
const backendUrl = new URL(config.backend);
if (publicUrl.protocol !== 'https:' || backendUrl.protocol !== 'https:' ||
    publicUrl.hostname !== 'localhost' || backendUrl.hostname !== 'localhost' ||
    publicUrl.port === backendUrl.port || !/^[a-z0-9-]+$/.test(config.device_header)) {
  throw new Error('CONTROLLED_DEVICE_EDGE_CONFIG');
}
const read = key => fs.readFileSync(config[key]);
const proxyAgent = new https.Agent({
  keepAlive: true, maxSockets: 8,
  cert: read('proxy_certificate'), key: read('proxy_private_key'),
  ca: read('backend_ca'), rejectUnauthorized: true,
});
const server = https.createServer({
  cert: read('edge_certificate'), key: read('edge_private_key'),
  ca: read('device_ca'), requestCert: true, rejectUnauthorized: false,
  minVersion: 'TLSv1.2',
}, (request, response) => {
  const leaf = request.socket.getPeerCertificate();
  if (leaf.raw && !request.socket.authorized) {
    response.writeHead(403, { 'cache-control': 'no-store' }); response.end(); return;
  }
  // Strip all caller-selected evidence and routing fields, even on a valid TLS
  // connection; the caller cannot replace the actually authenticated leaf.
  const headers = { ...request.headers };
  delete headers[config.device_header];
  delete headers['x-forwarded-for'];
  delete headers['forwarded'];
  headers.host = publicUrl.host;
  headers['x-forwarded-proto'] = 'https';
  headers['x-forwarded-for'] = '127.0.0.1';
  if (leaf.raw && request.socket.authorized) {
    const pem = `-----BEGIN CERTIFICATE-----\n${leaf.raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
    headers[config.device_header] = encodeURIComponent(pem);
  }
  const upstream = https.request({
    hostname: backendUrl.hostname, port: backendUrl.port, servername: 'localhost',
    method: request.method, path: request.url, headers, agent: proxyAgent,
  }, incoming => {
    response.writeHead(incoming.statusCode, incoming.headers);
    pipeline(incoming, response, () => {});
  });
  upstream.on('error', () => {
    if (!response.headersSent) response.writeHead(502, { 'cache-control': 'no-store' });
    response.end();
  });
  pipeline(request, upstream, () => {});
});
server.requestTimeout = 15000;
server.headersTimeout = 10000;
server.listen(Number(publicUrl.port), '127.0.0.1', () => process.stderr.write('CONTROLLED_DEVICE_EDGE_READY\n'));
const close = () => { proxyAgent.destroy(); server.close(); };
process.once('SIGTERM', close); process.once('SIGINT', close);
