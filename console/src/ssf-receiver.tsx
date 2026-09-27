/** Operator controls for the inbound Shared Signals receiver (ast-s36.26.7). */
import { useState } from 'react';
import type { JSX } from 'react';
import { mutate, read, type Session } from './api';
import { toast } from './components/ui/toast';
import { Actions, Button, Message, Panel } from './ui';
import { userIdForUsername } from './user-lookup';
import type { Directory } from './users';

const SUBJECT_PATH = 'ssf/receiver/subjects';

type Change = 'bind' | 'remove';

/** A mapping is identified by all three values; there is no list API yet. */
export function SsfReceiverSubjects({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [peer, setPeer] = useState('');
  const [subjectText, setSubjectText] = useState('{"format":"opaque","id":""}');
  const [user, setUser] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'success' | 'error'; text: string } | null>(null);
  const writable = session.scopes.includes('admin.ssf:write');

  const change = async (operation: Change): Promise<void> => {
    setMessage(null);
    const peerId = peer.trim();
    const username = user.trim();
    if (peerId.length === 0 || peerId.length > 255) {
      setMessage({ tone: 'error', text: 'Enter a registered peer client ID (up to 255 characters).' });
      return;
    }
    if (!username) {
      setMessage({ tone: 'error', text: 'Enter the local user’s username.' });
      return;
    }
    if (new TextEncoder().encode(subjectText).length > 4096) {
      setMessage({ tone: 'error', text: 'The subject document must be under 4 KB.' });
      return;
    }
    let subject: unknown;
    try {
      subject = JSON.parse(subjectText) as unknown;
    } catch {
      setMessage({ tone: 'error', text: 'Enter a valid JSON subject identifier.' });
      return;
    }
    if (subject === null || typeof subject !== 'object' || Array.isArray(subject)) {
      setMessage({ tone: 'error', text: 'The subject identifier must be a JSON object.' });
      return;
    }
    setBusy(true);
    try {
      const userId = await userIdForUsername(username, async (path) => await read(path) as Directory);
      if (userId === null) {
        setMessage({ tone: 'error', text: `No user has the username “${username}”.` });
        return;
      }
      const verb = operation === 'bind' ? 'PUT' : 'DELETE';
      await mutate(SUBJECT_PATH, verb, session, { peer_client_id: peerId, subject, user_id: userId });
      const text = operation === 'bind'
        ? `The peer subject is now bound to ${username}.`
        : `The peer subject mapping for ${username} was removed.`;
      setMessage({ tone: 'success', text });
      toast.success('Shared signals mapping updated', text);
    } catch (error) {
      const text = error instanceof Error ? error.message : 'The mapping change was refused.';
      setMessage({ tone: 'error', text });
      toast.error('Mapping unchanged', text);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      id="ssf-receiver-subjects"
      title="Inbound subject mapping"
      description="Link a trusted sender’s subject identifier to a local user before its security events can act on that account. Only clients configured for SSF reception are eligible."
    >
      <p className="muted">
        The server cannot list existing mappings yet. To remove a mapping, enter the same peer,
        subject identifier and local username used when it was bound. Keep a record of those values
        in your operator system.
      </p>
      {message !== null && <Message tone={message.tone}>{message.text}</Message>}
      {writable && session.scopes.includes('admin.users:read') ? (
        <form className="flex flex-col gap-3" onSubmit={(event) => { event.preventDefault(); void change('bind'); }}>
          <label className="flex flex-col gap-1" htmlFor="ssf-receiver-peer">
            Peer client ID
            <input
              id="ssf-receiver-peer"
              value={peer}
              onChange={(event) => setPeer(event.target.value)}
              maxLength={255}
              autoComplete="off"
              required
              disabled={busy}
            />
          </label>
          <label className="flex flex-col gap-1" htmlFor="ssf-receiver-subject">
            Subject identifier (JSON)
            <textarea
              id="ssf-receiver-subject"
              value={subjectText}
              onChange={(event) => setSubjectText(event.target.value)}
              rows={4}
              spellCheck={false}
              autoComplete="off"
              required
              disabled={busy}
            />
          </label>
          <p className="muted">
            Example: <code>{'{"format":"opaque","id":"upstream-user-id"}'}</code>.
            Use the exact subject object the peer sends in its signed events.
          </p>
          <label className="flex flex-col gap-1" htmlFor="ssf-receiver-user">
            Local username
            <input
              id="ssf-receiver-user"
              value={user}
              onChange={(event) => setUser(event.target.value)}
              autoComplete="off"
              required
              disabled={busy}
            />
          </label>
          <Actions>
            <Button type="submit" disabled={busy}>Bind subject</Button>
            <Button type="button" disabled={busy} onClick={() => { void change('remove'); }}>
              Remove mapping
            </Button>
          </Actions>
        </form>
      ) : (
        <p className="muted">You need Shared Signals write access and user directory access to change subject mappings by username.</p>
      )}
    </Panel>
  );
}
