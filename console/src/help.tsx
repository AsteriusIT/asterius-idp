import type { JSX, ReactNode } from 'react';
import type { Session } from './api';
import { visibleTo } from './navigation';
import { hrefOf } from './routes';
import { Panel, Screen } from './ui';
import { DeveloperGuide } from './developer-guide';

interface Guide {
  readonly title: string;
  readonly purpose: string;
  readonly route: string;
  readonly action: string;
  readonly steps: readonly string[];
}

const GUIDES: readonly Guide[] = [
  {
    title: 'Add a person', purpose: 'Create an account, then set up how it signs in and what it may access.',
    route: 'users', action: 'Open users',
    steps: [
      'Select Add user and enter a username. Add an email address if you have one.',
      'Open the new user to review their profile, credentials, sessions, and access.',
      'Use Groups or Roles on the user to grant access. Disabling an account ends its active sessions.',
    ],
  },
  {
    title: 'Connect an application', purpose: 'Register a client and collect the values its owner needs.',
    route: 'clients', action: 'Open applications',
    steps: [
      'Create an application and choose the kind of client that matches its integration.',
      'Enter the redirect URI supplied by the application owner. Save the client before sharing its connection details.',
      'Copy the issuer and client settings from the application page. Handle any displayed secret when it is first issued.',
    ],
  },
  {
    title: 'Build an access architecture', purpose: 'Draw and provision a web application, API, group, and roles together.',
    route: 'architecture', action: 'Open architecture builder',
    steps: [
      'Choose View to inspect a saved architecture, or Edit to open its fullscreen workspace. Start a new architecture from Web app + API or a blank diagram. Open the builder using the network icon beside your account menu. Add objects from the toolbar; select one to edit its settings in the right pane. Click the canvas background for architecture settings.',
      'Enter application callback URLs and choose a public JWKS URL or paste public JWKS JSON. Enter the API audience and permissions. Connect applications to APIs and role leaves, and groups to roles, by dragging between their handles. Save draft preserves the diagram without changing live resources.',
      'Preview the saved revision. Changes to settings owned by this flow appear as updates; manual changes to those settings appear as conflicts. If Apply stops partway through, preview again to see what completed and retry safely.',
      'Open a linked resource to return to its creating flow. Use Delete draft object for objects that have not been linked to a resource. For linked objects, Remove from diagram leaves the live resource in place. Select a connection on the canvas to remove it. Streams, users and external identity providers are diagram context only. Providers may connect only to groups or users; these links do not configure sign-in or membership.',
    ],
  },
  {
    title: 'Give a group access', purpose: 'Use one group to manage access for several people.',
    route: 'groups', action: 'Open groups',
    steps: [
      'Create a group with a clear display name and a stable machine name.',
      'In Members, add people by their exact username.',
      'In Roles, grant an application role. New authorization decisions use the membership immediately; existing tokens last until they expire.',
    ],
  },
  {
    title: 'Investigate a problem', purpose: 'Find the event, identify the affected user, and check current health.',
    route: 'audit', action: 'Open audit trail',
    steps: [
      'Start with the Audit trail and narrow by time, actor, or action.',
      'Open the user to inspect sign-in methods and active sessions if the event concerns an account.',
      'Check Overview for current activity and health. Mail delivery and Shared signals show delivery failures when those features are enabled.',
    ],
  },
  {
    title: 'Work in another tenant', purpose: 'Change the active tenant before editing its users or applications.',
    route: 'tenants', action: 'Open tenants',
    steps: [
      'Use the tenant selector in the top bar, or open Tenants to inspect the deployment list.',
      'After switching, check the tenant name in the top bar before making changes.',
      'A tenant whose issuer uses another host opens there. Browser sessions do not cross hosts. For one shared admin sign-in, give each tenant its own /t/<tenant id> issuer on the same domain when provisioning it.',
    ],
  },
  {
    title: 'Set up SCIM provisioning', purpose: 'Check whether an automation client is ready to create and update users.',
    route: 'scim', action: 'Open SCIM provisioning',
    steps: [
      'Register an application for the external identity provider, then inspect it on the SCIM provisioning page.',
      'Follow the readiness checks for client credentials, DPoP, audience, and SCIM read and write scopes.',
      'Give the provider the tenant-specific SCIM base URL and audience shown on that page.',
    ],
  },
  {
    title: 'Trust a SAML service provider', purpose: 'Allow one approved service provider to use this tenant’s SAML identity provider.',
    route: 'saml', action: 'Open SAML identity provider',
    steps: [
      'Check that the tenant has an active IdP signing certificate.',
      'Under Trusted service providers, add the exact entity ID and HTTPS assertion consumer URL supplied by the service provider.',
      'Review the signing requirement before saving. Remove a trust when the service provider is retired.',
    ],
  },
  {
    title: 'Rotate signing keys', purpose: 'Publish a successor key while existing tokens finish their lifetime.',
    route: 'keys', action: 'Open signing keys',
    steps: [
      'Review the active key and the rotation schedule for its algorithm.',
      'Rotate to create a successor. Check the public JWK set that applications fetch.',
      'Retire an older key only after its propagation and grace period has passed.',
    ],
  },
];

function GuideCard({ guide }: Readonly<{ guide: Guide }>): JSX.Element {
  return (
    <article className="guide-card">
      <div>
        <h3>{guide.title}</h3>
        <p className="muted">{guide.purpose}</p>
      </div>
      <ol>{guide.steps.map((step) => <li key={step}>{step}</li>)}</ol>
      <a className="guide-link" href={hrefOf(guide.route)}>{guide.action} <span aria-hidden="true">→</span></a>
    </article>
  );
}

function Term({ name, children }: Readonly<{ name: string; children: ReactNode }>): JSX.Element {
  return <div className="guide-term"><dt>{name}</dt><dd>{children}</dd></div>;
}

export function Help({ session }: Readonly<{ session: Session }>): JSX.Element {
  const allowed = new Set(visibleTo(session).map((destination) => destination.route));
  const guides = GUIDES.filter((guide) => allowed.has(guide.route));
  return (
    <Screen title="Help & guides" description="Common tasks in this console, with links you can use from this account.">
      <Panel title="Get something done" description="Choose a task. Each guide ends at the screen where you can do it.">
        {guides.length > 0
          ? <div className="guide-grid">{guides.map((guide) => <GuideCard key={guide.title} guide={guide} />)}</div>
          : <p className="muted">Your current role has no management screens. Ask an administrator which access you need.</p>}
      </Panel>
      <DeveloperGuide />
      <Panel title="Words used here" description="A few terms you will see across the console.">
        <dl className="guide-terms">
          <Term name="Tenant">An isolated identity workspace. Users, applications, and policy belong to a tenant.</Term>
          <Term name="Application">Software that sends people here to sign in. Its registration defines where sign-in can return.</Term>
          <Term name="Group">A set of users that can receive application roles together.</Term>
          <Term name="Role">A grant that affects what a user may do. Your console role also controls which screens and actions you can use.</Term>
          <Term name="Session">A person's current browser sign-in. Ending it requires them to sign in again.</Term>
        </dl>
      </Panel>
      <Panel title="When something fails">
        <div className="guide-grid">
          <div className="guide-note"><strong>A screen or button is missing</strong><p>Your role may not allow that action in this tenant. The Overview page shows your active role; ask a deployment administrator to review access.</p></div>
          <div className="guide-note"><strong>A save is refused</strong><p>Read the message beside the form, correct the named field, and try again. The draft stays on screen where the form supports it.</p></div>
          <div className="guide-note"><strong>A tenant switch asks for sign-in</strong><p>Check the target issuer in Tenants. A different host cannot use this browser session. An existing tenant needs a planned issuer migration before it can move to the shared domain.</p></div>
        </div>
      </Panel>
    </Screen>
  );
}
