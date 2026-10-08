import test from 'node:test';
import assert from 'node:assert/strict';
import { publicResult, validOrigin } from './lab.mjs';
test('browser result cannot expose token credentials or auth request identifiers', () => {
 assert.deepEqual(publicResult({access_token:'secret',refresh_token:'secret',id_token:'secret',device_code:'secret',auth_req_id:'secret',active:true,scope:'openid'}),{active:true,scope:'openid'});
});
test('mutation origin requires exact scheme host and port', () => {
 assert.equal(validOrigin('https://host:8446','https://host:8446/protocols'),true);
 for (const origin of [undefined,'https://host','http://host:8446','https://foreign:8446','null']) assert.equal(validOrigin(origin,'https://host:8446/protocols'),false);
});
