#!/usr/bin/env node
// Actual disposable TLS transport controls. This does NOT exercise Asterius.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import https from 'node:https';
import net from 'node:net';
import { spawn, execFileSync } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const directory = path.dirname(fileURLToPath(import.meta.url));
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'asterius-managed-device.transport.'));
fs.rmdirSync(root);
let edge, backend;
const results = [];
const read = name => fs.readFileSync(path.join(root,name));
const fingerprint = value => createHash('sha256').update(value).digest('hex');
const expect = (name, condition) => {
  if (!condition) throw new Error(`DEVICE_TRANSPORT_CONTROL_FAILED:${name}`);
  results.push({name,status:'pass'});
};
const request = (port, options={}) => new Promise(resolve => {
  const outgoing = https.request({hostname:'127.0.0.1',servername:'localhost',port,
    path:'/controlled',ca:read('backend-ca.pem'),rejectUnauthorized:true,method:'GET',
    ...(options || {}),
  }, incoming => {
    let body=''; incoming.setEncoding('utf8');
    incoming.on('data',chunk=>{body+=chunk; if(body.length>8192) incoming.destroy();});
    incoming.on('end',()=>resolve({status:incoming.statusCode,body}));
  });
  outgoing.setTimeout(3000,()=>outgoing.destroy());
  outgoing.on('error',()=>resolve({status:0,body:''})); outgoing.end();
});
try {
  execFileSync('bash',[path.join(directory,'prepare-pki.sh'),root],{stdio:['ignore','pipe','pipe'],timeout:30000});
  const pin=fingerprint(new X509Certificate(read('proxy-cert.pem')).raw);
  backend=https.createServer({cert:read('backend-cert.pem'),key:read('backend-key.pem'),
    ca:read('proxy-ca.pem'),requestCert:true,rejectUnauthorized:true,
  },(incoming,response)=>{
    const peer=incoming.socket.getPeerCertificate();
    if(!incoming.socket.authorized || !peer.raw || fingerprint(peer.raw)!==pin) {
      response.writeHead(403);response.end();return;
    }
    const header=incoming.headers['x-controlled-device-cert'];
    let observed=null;
    if(typeof header==='string') {
      try { observed=fingerprint(new X509Certificate(decodeURIComponent(header)).raw); }
      catch { response.writeHead(400);response.end();return; }
    }
    response.writeHead(200,{'content-type':'application/json'});
    response.end(JSON.stringify({leaf:observed}));
  });
  await new Promise(resolve=>backend.listen(0,'127.0.0.1',resolve));
  const backendPort=backend.address().port;
  const reserve=net.createServer();
  await new Promise(resolve=>reserve.listen(0,'127.0.0.1',resolve));
  const edgePort=reserve.address().port;
  await new Promise(resolve=>reserve.close(resolve));
  const config={issuer:`https://localhost:${edgePort}`,backend:`https://localhost:${backendPort}`,
    device_header:'x-controlled-device-cert',edge_certificate:path.join(root,'edge-cert.pem'),
    edge_private_key:path.join(root,'edge-key.pem'),device_ca:path.join(root,'device-ca.pem'),
    proxy_certificate:path.join(root,'proxy-cert.pem'),proxy_private_key:path.join(root,'proxy-key.pem'),
    backend_ca:path.join(root,'backend-ca.pem')};
  const configPath=path.join(root,'edge.json');fs.writeFileSync(configPath,JSON.stringify(config),{mode:0o600});
  edge=spawn(process.execPath,[path.join(directory,'proxy.mjs'),configPath],{stdio:['ignore','ignore','pipe']});
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(new Error('DEVICE_EDGE_READY_TIMEOUT')),5000);
    edge.stderr.on('data',data=>{if(data.toString().includes('CONTROLLED_DEVICE_EDGE_READY')){clearTimeout(timer);resolve();}});
    edge.once('exit',()=>{clearTimeout(timer);reject(new Error('DEVICE_EDGE_BOOTSTRAP_FAILED'));});
  });
  const known=fingerprint(new X509Certificate(read('device-cert.pem')).raw);
  const spoof=encodeURIComponent(read('unrelated-device-cert.pem').toString());
  const legitimate={cert:read('device-cert.pem'),key:read('device-key.pem')};
  let response=await request(edgePort,{headers:{'x-controlled-device-cert':spoof}});
  expect('caller-header-without-device-possession-stripped',response.status===200 && JSON.parse(response.body).leaf===null);
  response=await request(edgePort,legitimate);
  expect('actual-approved-device-handshake-forwarded-over-authenticated-hop',response.status===200 && JSON.parse(response.body).leaf===known);
  response=await request(edgePort,{...legitimate,headers:{'x-controlled-device-cert':spoof}});
  expect('caller-header-cannot-replace-authenticated-leaf',response.status===200 && JSON.parse(response.body).leaf===known);
  response=await request(edgePort,{cert:read('unrelated-device-cert.pem'),key:read('unrelated-device-key.pem')});
  expect('unrelated-device-ca-refused',response.status===403 || response.status===0);
  response=await request(edgePort,{cert:read('wrong-usage-device-cert.pem'),key:read('wrong-usage-device-key.pem')});
  expect('server-only-usage-device-refused',response.status===403 || response.status===0);
  response=await request(backendPort,{headers:{'x-controlled-device-cert':spoof}});
  expect('direct-header-without-authenticated-proxy-hop-refused',response.status===0);
  response=await request(backendPort,{cert:read('unpinned-proxy-cert.pem'),key:read('unpinned-proxy-key.pem')});
  expect('chain-valid-unpinned-proxy-leaf-refused',response.status===403);
  response=await request(backendPort,legitimate);
  expect('device-leaf-cannot-authenticate-separate-proxy-hop',response.status===0);
  console.log(JSON.stringify({component:'controlled Node TLS edge/backend',asterius_enforcement:'not_exercised',node_version:process.version,observed_at:new Date().toISOString(),runner_sha256:fingerprint(fs.readFileSync(fileURLToPath(import.meta.url))),edge_sha256:fingerprint(fs.readFileSync(path.join(directory,'proxy.mjs'))),pki_preparer_sha256:fingerprint(fs.readFileSync(path.join(directory,'prepare-pki.sh'))),checks:results}));
} finally {
  if(edge && edge.exitCode===null) { edge.kill('SIGTERM'); await new Promise(resolve=>edge.once('exit',resolve)); }
  if(backend) { backend.closeAllConnections(); await new Promise(resolve=>backend.close(resolve)); }
  fs.rmSync(root,{recursive:true,force:true});
}
