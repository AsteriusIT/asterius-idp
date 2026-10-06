import { CheckIcon, ChevronsUpDownIcon, Code2Icon, FlaskConicalIcon } from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { CopyValue } from './components/copy-value';
import { JsonView } from './components/json-view';
import { YamlView } from './components/yaml-view';
import { Command, CommandGroup, CommandInput, CommandItem, CommandList } from './components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from './components/ui/popover';
import { Button, Message, Panel, Screen } from './ui';
import { Field, FieldGroup, FieldLabel } from './components/ui/field';
import { InputGroup, InputGroupAddon, InputGroupButton, InputGroupText, InputGroupTextarea } from './components/ui/input-group';
import { Empty, EmptyHeader, EmptyMedia, EmptyTitle, EmptyDescription } from './components/ui/empty';
import { decodeJwt } from './token-console-model';

interface UserOption { readonly user_id: string; readonly username: string; readonly email: string | null; readonly status: string }
interface UserPage { readonly items: readonly UserOption[]; readonly next_cursor: string | null }
type UserLoad = { readonly kind: 'loading' } | { readonly kind: 'failed'; readonly message: string } | { readonly kind: 'ready'; readonly page: UserPage };
interface ApplicationOption { readonly client_id: string; readonly client_name: string }
interface ApplicationPage { readonly items: readonly ApplicationOption[]; readonly next_cursor: string | null }
type ApplicationLoad = { readonly kind: 'loading' } | { readonly kind: 'failed'; readonly message: string } | { readonly kind: 'ready'; readonly page: ApplicationPage };

export function TokenConsole({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [applicationOpen, setApplicationOpen] = useState(false);
  const [applicationQuery, setApplicationQuery] = useState('');
  const [applications, setApplications] = useState<ApplicationLoad>({ kind: 'loading' });
  const [application, setApplication] = useState<ApplicationOption | null>(null);
  const applicationRequestId = useRef(0);
  const [userOpen, setUserOpen] = useState(false);
  const [userQuery, setUserQuery] = useState('');
  const [users, setUsers] = useState<UserLoad>({ kind: 'loading' });
  const [selectedUser, setSelectedUser] = useState<UserOption | null>(null);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const userRequestId = useRef(0);
  const mayIssue = session.scopes.includes('admin.test_tokens:write');

  const searchApplications = useCallback((term: string) => {
    const current = ++applicationRequestId.current;
    setApplications({ kind: 'loading' });
    read(`clients?status=active${term.trim() ? `&q=${encodeURIComponent(term.trim())}` : ''}`).then(
      body => { if (current === applicationRequestId.current) setApplications({ kind: 'ready', page: body as ApplicationPage }); },
      reason => { if (current === applicationRequestId.current) setApplications({ kind: 'failed', message: reason instanceof Error ? reason.message : 'Applications could not be loaded.' }); },
    );
  }, []);
  useEffect(() => {
    if (!applicationOpen || !mayIssue) return;
    const timer = window.setTimeout(() => searchApplications(applicationQuery), applicationQuery ? 220 : 0);
    return () => window.clearTimeout(timer);
  }, [applicationOpen, mayIssue, applicationQuery, searchApplications]);

  const searchUsers = useCallback((term: string) => {
    const current = ++userRequestId.current;
    setUsers({ kind: 'loading' });
    read(`users?status=active${term.trim() ? `&q=${encodeURIComponent(term.trim())}` : ''}`).then(
      body => { if (current === userRequestId.current) setUsers({ kind: 'ready', page: body as UserPage }); },
      reason => { if (current === userRequestId.current) setUsers({ kind: 'failed', message: reason instanceof Error ? reason.message : 'Users could not be loaded.' }); },
    );
  }, []);
  useEffect(() => {
    if (!userOpen || !mayIssue) return;
    const timer = window.setTimeout(() => searchUsers(userQuery), userQuery ? 220 : 0);
    return () => window.clearTimeout(timer);
  }, [userOpen, mayIssue, userQuery, searchUsers]);

  const issue = async (): Promise<void> => {
    if (application === null || selectedUser === null || busy || !mayIssue) return;
    setBusy(true); setError(null); setToken('');
    try {
      const result = await mutate(`clients/${encodeURIComponent(application.client_id)}/test-token`, 'POST', session, { user_id: selectedUser.user_id }) as { id_token: string };
      setToken(result.id_token);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'The test token could not be issued.');
    } finally { setBusy(false); }
  };
  const decoded = token ? decodeJwt(token) : null;

  return <Screen className="token-console-page" title="Token test console" description={`Issue and inspect a test ID token using an application and an active user in ${session.workspace}.`}>
    <section className="token-console" aria-label="Token workspace">
      <Panel title="Issue a test token" description="Choose an application and user to preview the ID token your integration receives.">
      <Message tone="info">An administrator issues the token as the selected user. It expires after 60 seconds, carries <code>asterius_test: true</code>, and does not claim the user signed in.</Message>
      {!mayIssue ? <Message tone="info">Issuing test tokens requires administrator access.</Message> : <FieldGroup className="token-console-controls">
        <Field><FieldLabel id="token-test-application-label">Application</FieldLabel>
          <Popover open={applicationOpen} onOpenChange={value => { setApplicationOpen(value); if (value) setApplicationQuery(''); }}>
            <PopoverTrigger render={<Button variant="secondary" role="combobox" aria-labelledby="token-test-application-label" aria-expanded={applicationOpen} className="kubernetes-picker-trigger" disabled={busy}><span>{application === null ? 'Select an active application' : `${application.client_name} (${application.client_id})`}</span><ChevronsUpDownIcon aria-hidden="true" /></Button>} />
            <PopoverContent align="start" className="kubernetes-picker-popover"><Command shouldFilter={false}>
              <CommandInput value={applicationQuery} onValueChange={setApplicationQuery} placeholder="Search applications…" aria-label="Search applications for test token" />
              <CommandList>
                {applications.kind === 'loading' && <p className="kubernetes-picker-note" role="status">Searching applications…</p>}
                {applications.kind === 'failed' && <div className="kubernetes-picker-note"><p>{applications.message}</p><Button small onClick={() => searchApplications(applicationQuery)}>Retry</Button></div>}
                {applications.kind === 'ready' && applications.page.items.length === 0 && <p className="kubernetes-picker-note">No active applications match.</p>}
                <CommandGroup>{applications.kind === 'ready' && applications.page.items.map(item => <CommandItem key={item.client_id} value={item.client_id} onSelect={() => { setApplication(item); setApplicationOpen(false); setToken(''); setError(null); }}><span className="kubernetes-picker-option"><strong>{item.client_name}</strong><small>{item.client_id}</small></span>{application?.client_id === item.client_id && <CheckIcon className="ml-auto size-4" aria-hidden="true" />}</CommandItem>)}</CommandGroup>
              </CommandList>
              {applications.kind === 'ready' && applications.page.next_cursor !== null && <p className="kubernetes-picker-note">More results exist. Refine your search.</p>}
            </Command></PopoverContent>
          </Popover>
        </Field>
        <Field><FieldLabel id="token-test-user-label">User</FieldLabel>
          <Popover open={userOpen} onOpenChange={value => { setUserOpen(value); if (value) setUserQuery(''); }}>
            <PopoverTrigger render={<Button variant="secondary" role="combobox" aria-labelledby="token-test-user-label" aria-expanded={userOpen} className="kubernetes-picker-trigger" disabled={busy}><span>{selectedUser === null ? 'Select an active user' : selectedUser.username}</span><ChevronsUpDownIcon aria-hidden="true" /></Button>} />
            <PopoverContent align="start" className="kubernetes-picker-popover"><Command shouldFilter={false}>
              <CommandInput value={userQuery} onValueChange={setUserQuery} placeholder="Search users…" aria-label="Search users for test token" />
              <CommandList>
                {users.kind === 'loading' && <p className="kubernetes-picker-note" role="status">Searching users…</p>}
                {users.kind === 'failed' && <div className="kubernetes-picker-note"><p>{users.message}</p><Button small onClick={() => searchUsers(userQuery)}>Retry</Button></div>}
                {users.kind === 'ready' && users.page.items.length === 0 && <p className="kubernetes-picker-note">No active users match.</p>}
                <CommandGroup>{users.kind === 'ready' && users.page.items.map(user => <CommandItem key={user.user_id} value={user.user_id} onSelect={() => { setSelectedUser(user); setUserOpen(false); setToken(''); setError(null); }}><span className="kubernetes-picker-option"><strong>{user.username}</strong><small>{user.email ?? user.user_id}</small></span>{selectedUser?.user_id === user.user_id && <CheckIcon className="ml-auto size-4" aria-hidden="true" />}</CommandItem>)}</CommandGroup>
              </CommandList>
              {users.kind === 'ready' && users.page.next_cursor !== null && <p className="kubernetes-picker-note">More results exist. Refine your search.</p>}
            </Command></PopoverContent>
          </Popover>
        </Field>
        <Button variant="primary" disabled={application === null || selectedUser === null || busy} onClick={() => void issue()}><FlaskConicalIcon data-icon="inline-start" aria-hidden="true" />{busy ? 'Issuing…' : 'Issue test ID token'}</Button>
      </FieldGroup>}
      {error && <Message tone="error">{error}</Message>}
      </Panel>
      <div className="token-console-grid">
        <Panel title="Encoded token" description="Paste a JWT or issue one above. It stays in this tab until you clear it or leave.">
          <InputGroup className="token-source-editor">
            <InputGroupTextarea aria-label="Encoded token" aria-describedby="token-source-help" aria-invalid={token.trim() !== '' && decoded === null}
              spellCheck={false} autoCapitalize="off" autoCorrect="off" readOnly={busy} value={token} onChange={event => setToken(event.target.value)}
              placeholder="eyJ… Paste a three-part JWT" rows={12} />
            <InputGroupAddon align="block-end">
              <InputGroupText>{token.length} characters</InputGroupText>
              <span className="token-source-actions">{token && <CopyValue value={token} label="Copy token" />}<InputGroupButton disabled={!token || busy} onClick={() => setToken('')}>Clear</InputGroupButton></span>
            </InputGroupAddon>
          </InputGroup>
          <p className="muted" id="token-source-help">{token.trim() !== '' && decoded === null ? 'This JWT could not be decoded. Check that it has three parts and JSON header and claims.' : 'Header and claims are decoded locally. The signature is not verified.'}</p>
        </Panel>
        <Panel title="Decoded token" description="Inspect the header and claims. Decoding does not verify the signature or grant access.">
          {decoded ? <><h4>Header</h4><JsonView value={decoded.header} label="JWT header" /><h4>Claims</h4><JsonView value={decoded.claims} label="JWT claims" /><details><summary>Claims as YAML</summary><YamlView value={decoded.claims} label="JWT claims YAML" /></details></> : <Empty className="token-decode-empty">
            <EmptyHeader><EmptyMedia variant="icon"><Code2Icon aria-hidden="true" /></EmptyMedia><EmptyTitle>No token to inspect</EmptyTitle><EmptyDescription>Issue a test token or paste a JWT to see its header and claims here.</EmptyDescription></EmptyHeader>
          </Empty>}
        </Panel>
      </div>
    </section>
  </Screen>;
}
