import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import {
  generateKeyPair,
  exportJWK,
} from "../../tools/kubernetes-login/node_modules/jose/dist/webapi/index.js";
const directory = process.env.KUBE_E2E_DIR,
  database = process.env.E2E_DATABASE_URL;
if (
  !directory ||
  !database ||
  !new URL(database).pathname.startsWith("/ast_dd1y14")
)
  throw Error("isolated_fixture_required");
const config = JSON.parse(readFileSync(directory + "/broker.json", "utf8"));
for (const [id, tenant, issuer] of [
  ["cluster-b", "e2e-webauthn", "https://localhost:9447/t/e2e-webauthn"],
  ["cluster-c", "e2e", "https://127.0.0.1:9447/t/e2e"],
]) {
  const metadata = await (
    await fetch(issuer + "/.well-known/openid-configuration")
  ).json();
  const { publicKey, privateKey } = await generateKeyPair("ES256", {
      extractable: true,
    }),
    keyId = "kubernetes-" + id;
  const response = await fetch(metadata.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Disposable negative " + id,
      redirect_uris: [config.origin + "/callback/" + id],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: "openid offline_access",
      token_endpoint_auth_method: "private_key_jwt",
      application_type: "web",
      id_token_signed_response_alg: "ES256",
      dpop_bound_access_tokens: true,
      managed_groups_claim: true,
      jwks: {
        keys: [
          {
            ...(await exportJWK(publicKey)),
            kid: keyId,
            alg: "ES256",
            use: "sig",
          },
        ],
      },
    }),
  });
  if (response.status !== 201)
    throw Error("alternate_registration_failed_" + response.status);
  const { client_id: clientId } = await response.json();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(clientId))
    throw Error("unexpected_client_id");
  execFileSync(
    "psql",
    [
      database,
      "-q",
      "-v",
      "ON_ERROR_STOP=1",
      "-c",
      `UPDATE tenants SET settings=jsonb_set(coalesce(settings,'{}'::jsonb),'{options}','{"allow_non_fapi_clients":true}'::jsonb) WHERE tenant_id='${tenant}';UPDATE clients SET compliance_profile='oidc',managed_groups_claim=true WHERE tenant_id='${tenant}' AND client_id='${clientId}';INSERT INTO kubernetes_profiles(tenant_id,client_id,cluster_id,namespace,group_ids,revision) VALUES('${tenant}','${clientId}','${id}','human-access','{}'::uuid[],1);`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  config.clusters.push({
    id,
    issuer,
    clientId,
    keyId,
    privateJwk: await exportJWK(privateKey),
  });
}
writeFileSync(directory + "/broker.json", JSON.stringify(config), {
  mode: 0o600,
});
process.stdout.write(
  "Prepared actual Asterius alternate audience and issuer clients.\n",
);
