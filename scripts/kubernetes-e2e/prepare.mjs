import { writeFileSync, readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  generateKeyPair,
  exportJWK,
} from "../../tools/kubernetes-login/node_modules/jose/dist/webapi/index.js";
const directory = process.env.KUBE_E2E_DIR,
  issuer = "https://localhost:9447/t/e2e-webauthn",
  broker = "https://localhost:9449",
  database = process.env.E2E_DATABASE_URL;
if (
  !directory ||
  !database ||
  !new URL(database).pathname.startsWith("/ast_dd1y14")
)
  throw Error("isolated_fixture_required");
const sql = (value) =>
  execFileSync("psql", [database, "-q", "-v", "ON_ERROR_STOP=1", "-c", value], {
    stdio: ["ignore", "pipe", "pipe"],
  });
sql(
  `UPDATE tenants SET settings=jsonb_set(coalesce(settings,'{}'::jsonb),'{options}','{"allow_non_fapi_clients":true}'::jsonb) || jsonb_build_object('refresh','{"absolute_lifetime_seconds":28800,"idle_lifetime_seconds":900,"bind_to_dpop_key":true,"rotation":{"mode":"none"}}'::jsonb) WHERE tenant_id='e2e-webauthn'`,
);
const metadata = await (
  await fetch(issuer + "/.well-known/openid-configuration")
).json();
const { publicKey, privateKey } = await generateKeyPair("ES256", {
    extractable: true,
  }),
  keyId = "kubernetes-e2e-client";
const response = await fetch(metadata.registration_endpoint, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    client_name: "Disposable Kubernetes broker",
    redirect_uris: [broker + "/callback/cluster-a"],
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
    backchannel_logout_uri: broker + "/backchannel/cluster-a",
    backchannel_logout_session_required: true,
  }),
});
if (response.status !== 201)
  throw Error(
    "registration_failed_" + response.status + " " + (await response.text()),
  );
const registered = await response.json(),
  clientId = registered.client_id;
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(clientId)) throw Error("unexpected_client_id");
sql(`UPDATE clients SET compliance_profile='oidc',managed_groups_claim=true WHERE tenant_id='e2e-webauthn' AND client_id='${clientId}';
INSERT INTO managed_groups(tenant_id,group_id,name,display_name,created_at,updated_at) VALUES('e2e-webauthn','10000000-0000-4000-8000-000000000001','kube-readers','Kubernetes readers',now(),now());
INSERT INTO group_memberships(tenant_id,group_id,user_id,created_at) VALUES('e2e-webauthn','10000000-0000-4000-8000-000000000001','3f1d5c2a-0000-4000-8000-000000000001',now());
INSERT INTO kubernetes_profiles(tenant_id,client_id,cluster_id,namespace,group_ids,revision) VALUES('e2e-webauthn','${clientId}','cluster-a','human-access',ARRAY['10000000-0000-4000-8000-000000000001'::uuid],1);`);
writeFileSync(
  directory + "/broker.json",
  JSON.stringify({
    origin: broker,
    port: 8099,
    database: directory + "/broker/state.sqlite",
    storageKey: randomBytes(32).toString("base64"),
    clusters: [
      {
        id: "cluster-a",
        issuer,
        clientId,
        keyId,
        privateJwk: await exportJWK(privateKey),
      },
    ],
  }),
  { mode: 0o600 },
);
writeFileSync(
  directory + "/public.json",
  JSON.stringify({ issuer, broker, clientId, jwksUri: metadata.jwks_uri }),
  { mode: 0o600 },
);
writeFileSync(
  directory + "/kind.yaml",
  `kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: ${directory}/cert.pem
    containerPath: /etc/kubernetes/asterius-ca.pem
    readOnly: true
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        oidc-issuer-url: "${issuer}"
        oidc-client-id: "${clientId}"
        oidc-signing-algs: "ES256"
        oidc-username-claim: "sub"
        oidc-username-prefix: "asterius:e2e-webauthn:cluster-a:"
        oidc-groups-claim: "group_ids"
        oidc-groups-prefix: "asterius:e2e-webauthn:cluster-a:group:"
        oidc-ca-file: "/etc/kubernetes/asterius-ca.pem"
      extraVolumes:
      - name: asterius-ca
        hostPath: /etc/kubernetes/asterius-ca.pem
        mountPath: /etc/kubernetes/asterius-ca.pem
        readOnly: true
        pathType: File
`,
);
process.stdout.write(
  "Prepared isolated real Asterius OIDC client, managed-group release and cluster configuration.\n",
);
