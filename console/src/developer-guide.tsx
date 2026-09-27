import type { JSX } from 'react';
import { Panel } from './ui';

const RECIPES = [
  { name: 'TypeScript / Node.js', library: 'openid-client', url: 'https://github.com/panva/openid-client/blob/main/docs/README.md', steps: 'Build /login and /callback routes in your server or BFF. Use discovery, Authorization Code with PKCE, private_key_jwt, PAR and a DPoP handle for builder-created applications. Keep tokens and private keys on the server.' },
  { name: 'C# / ASP.NET Core', library: 'ASP.NET Core OpenID Connect', url: 'https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication', steps: 'Use cookie authentication for the web session and an OpenID Connect challenge for sign-in. Set Authority, ClientId and the exact callback URI. Verify support for the selected client authentication, signing algorithm, PAR and DPoP before choosing the FAPI profile.' },
  { name: 'Java / Spring', library: 'Spring Security', url: 'https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html', steps: 'Use oauth2Login for web sign-in and a resource server for APIs. Configure the exact issuer and API audience; authorize each endpoint by scope. JWT validation alone does not validate DPoP proofs: add verified proof handling for bound tokens.' },
  { name: 'Python / Flask or FastAPI', library: 'Authlib', url: 'https://docs.authlib.org/en/latest/oauth2/client/web/flask.html', steps: 'Use an OIDC client integration and discovery for the server-side login/callback flow. Store state, nonce, PKCE verifier and tokens in a server-side session. Confirm profile capabilities for your framework; a generic OAuth example is not a tested FAPI integration.' },
  { name: 'Rust / Axum or Actix', library: 'openidconnect', url: 'https://docs.rs/openidconnect/latest/openidconnect/', steps: 'Use discovery and a PKCE authorization-code flow with server-side session storage. Verify ID tokens through the library. Plan explicit PAR, client assertion and DPoP integration where the chosen client profile requires them.' },
] as const;

export function DeveloperGuide(): JSX.Element {
  return <Panel title="Developer integration guide — draft" description="Choose your application shape, collect its connection settings, then validate the complete sign-in and API flow. These recipes are implementation outlines, not generated or tested starter projects.">
    <div className="guide-grid">
      <article className="guide-card"><h3>Web application or SPA with a backend</h3><p>Keep OAuth tokens in the server or backend-for-frontend (BFF); the browser uses a Secure, HttpOnly session cookie with an appropriate SameSite policy and CSRF protection. The BFF preset adds a sign-in application plus a protected API with bff.access and a five-minute token lifetime. Supply callbacks, public keys and the API audience. The architecture builder creates a FAPI application: public JWKS, private_key_jwt, PAR and DPoP are required.</p></article>
      <article className="guide-card"><h3>SPA without a backend</h3><p>Create a public client in Applications when the tenant permits non-FAPI clients. Use Authorization Code with S256 PKCE and the configured DPoP policy. Never put a client secret or a confidential application private key in browser code. Check discovery and CORS before integration. The builder does not create this profile yet.</p></article>
      <article className="guide-card"><h3>API</h3><p>Register its exact audience URL and permissions, then authorize the calling application for that resource. Verify access-token signature, issuer, audience and expiry, require endpoint scopes, and validate any DPoP or certificate binding. An ID token is not an API access token. API-to-API and gateway links describe topology only; configure a caller client and authorized resource separately. Do not assume a gateway link grants access to downstream APIs.</p></article>
    </div>
    <h3>Connection settings to collect</h3>
    <p>Exact tenant issuer, client ID, registered callback URL, API audience, scopes, client authentication method and token binding. Discover endpoints from the issuer. Store private credentials in the application’s secret store; publish only public JWKS in the console.</p>
    <h3>Language recipes</h3>
    {RECIPES.map(recipe => <details className="developer-recipe" key={recipe.name}><summary>{recipe.name}</summary><p>{recipe.steps}</p><a href={recipe.url} target="_blank" rel="noreferrer">{recipe.library} documentation ↗</a></details>)}
    <h3>Before going live</h3>
    <p>Test sign-in, callback validation, logout and expiry; reject a wrong issuer, audience, scope, signature and missing or replayed binding proof. A drawn group or role does not enforce permissions in your API: implement authorization for every endpoint.</p>
  </Panel>;
}
