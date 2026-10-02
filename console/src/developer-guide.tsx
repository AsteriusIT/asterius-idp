import type { JSX } from 'react';
import { Panel } from './ui';
import { hrefOf } from './routes';
import { ArrowUpRightIcon } from 'lucide-react';

const RECIPES = [
  { name: 'TypeScript / Node.js', library: 'openid-client', url: 'https://github.com/panva/openid-client/blob/main/docs/README.md', steps: 'Build /login and /callback routes in your server or BFF. Use discovery, Authorization Code with PKCE, private_key_jwt, PAR and a DPoP handle for builder-created applications. Keep tokens and private keys on the server.' },
  { name: 'C# / ASP.NET Core', library: 'ASP.NET Core authentication', url: 'https://learn.microsoft.com/en-us/aspnet/core/security/authentication/configure-oidc-web-authentication', steps: 'Use cookie authentication for the web session and an external sign-in challenge. Set Authority, ClientId and the exact callback URI. Verify support for the selected client authentication, signing algorithm, PAR and DPoP before choosing the FAPI profile.' },
  { name: 'Java / Spring', library: 'Spring Security', url: 'https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html', steps: 'Use oauth2Login for web sign-in and a resource server for APIs. Configure the exact issuer and API audience; authorize each endpoint by scope. JWT validation alone does not validate DPoP proofs: add verified proof handling for bound tokens.' },
  { name: 'Python / Flask or FastAPI', library: 'Authlib', url: 'https://docs.authlib.org/en/latest/oauth2/client/web/flask.html', steps: 'Use an identity sign-in client and discovery for the server-side login/callback flow. Store state, nonce, PKCE verifier and tokens in a server-side session. Confirm profile capabilities for your framework; a generic OAuth example is not a tested FAPI integration.' },
  { name: 'Rust / Axum or Actix', library: 'openidconnect', url: 'https://docs.rs/openidconnect/latest/openidconnect/', steps: 'Use discovery and a PKCE authorization-code flow with server-side session storage. Verify ID tokens through the library. Plan explicit PAR, client assertion and DPoP integration where the chosen client profile requires them.' },
] as const;

export function DeveloperGuide({ available }: Readonly<{ available: ReadonlySet<string> }>): JSX.Element {
  return <div className="developer-guide">
    <Panel className="integration-start" title="From registration to your first sign-in" description="Start with the application’s connection settings. Use discovery to find the tenant’s endpoints.">
      <ol className="integration-checklist">
        <li><div><h4>Register your application</h4><p>Choose a client profile and register the exact callback URL. For a backend or BFF, supply public JWKS and keep private keys on your server.</p></div>{available.has('clients') && <a href={hrefOf('clients')}>Applications<ArrowUpRightIcon aria-hidden="true" /></a>}</li>
        <li><div><h4>Collect connection settings</h4><p>Copy the issuer, client ID, callback URL, scopes, authentication method and token binding from the application. Store private credentials in your secret manager.</p></div></li>
        <li><div><h4>Connect a protected API</h4><p>Register its audience and permissions, then authorize your application for that resource. Check audience and scopes on every endpoint.</p></div>{available.has('resources') && <a href={hrefOf('resources')}>Resource servers<ArrowUpRightIcon aria-hidden="true" /></a>}</li>
        <li><div><h4>Validate the complete flow</h4><p>Test sign-in, callback validation, logout and expiry. Reject wrong issuers, audiences, scopes and signatures, plus missing or replayed binding proofs.</p></div></li>
      </ol>
    </Panel>
    <Panel title="Choose your integration" description="Open the guidance that matches where your application runs.">
      <details className="developer-recipe"><summary>Web application or SPA with a backend</summary><div className="recipe-body">
        <p>Keep tokens in your server or backend-for-frontend (BFF). Use a Secure, HttpOnly browser session cookie with an appropriate SameSite policy and CSRF protection.</p>
        <p>The BFF preset creates a sign-in application and protected API with bff.access and a five-minute token lifetime. Supply callbacks, public keys and the API audience. Builder-created FAPI applications require public JWKS, private_key_jwt, PAR and DPoP.</p>
        {available.has('architecture') && <a href={hrefOf('architecture')}>Open architecture builder</a>}
      </div></details>
      <details className="developer-recipe"><summary>SPA without a backend</summary><div className="recipe-body">
        <p>Create a public client in Applications when your tenant permits non-FAPI clients. Use Authorization Code with S256 PKCE and the configured DPoP policy. Check discovery and CORS before integration.</p>
        <p>Never put a client secret or confidential application private key in browser code. The architecture builder does not create this profile yet.</p>
      </div></details>
      <details className="developer-recipe"><summary>Protected API</summary><div className="recipe-body">
        <p>Validate the access-token signature, issuer, audience and expiry. Require endpoint scopes and validate DPoP or certificate binding when configured. Use access tokens for API access; ID tokens describe a sign-in.</p>
        <p>Groups and roles need authorization checks in your API. API-to-API and gateway links in the builder describe topology only; configure caller credentials and resource access separately.</p>
      </div></details>
    </Panel>
    <Panel title="Language recipes" description="Implementation outlines with links to library documentation. These are not tested starter projects.">
      {RECIPES.map(recipe => <details className="developer-recipe" key={recipe.name}><summary><span>{recipe.name}</span><small>{recipe.library}</small></summary><div className="recipe-body"><p>{recipe.steps}</p><a href={recipe.url} target="_blank" rel="noreferrer">{recipe.library} documentation<ArrowUpRightIcon aria-hidden="true" /></a></div></details>)}
    </Panel>
  </div>;
}
