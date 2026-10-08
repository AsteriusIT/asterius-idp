import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import './style.css';

const api = import.meta.env.VITE_API_URL || '/financial-api';
function App() {
  const [session, setSession] = useState(null);
  useEffect(() => { fetch(`${api}/api/session`, { credentials: 'include' }).then(r => r.json()).then(setSession); }, []);
  return <div className="shell"><header><Link to="/" className="brand">Northstar <span>Financial</span></Link><nav><Link to="/accounts">Accounts</Link><Link to="/transfers">Transfers</Link></nav>{session?.authenticated ? <button onClick={async () => { await fetch(`${api}/auth/logout`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: '{}' }); location.reload(); }}>Sign out</button> : <a className="button" href={`${api}/auth/start`}>Sign in with Asterius</a>}</header><main><Routes><Route path="/" element={<Home authenticated={session?.authenticated} />} /><Route path="/accounts" element={<Accounts />} /><Route path="/transfers" element={<Transfers />} /></Routes></main></div>;
}
function Home({ authenticated }) { return <section className="hero"><p className="eyebrow">PRIVATE WEALTH · SECURE BY DESIGN</p><h1>Your money,<br /><em>in clear view.</em></h1><p className="lead">A small financial API protected by Asterius FAPI security controls: PAR, PKCE, private_key_jwt and DPoP.</p>{authenticated ? <Link className="button" to="/accounts">View your accounts</Link> : <a className="button" href={`${api}/auth/start`}>Open your secure workspace</a>}<div className="cards"><div><strong>€17,050.75</strong><span>Total balance</span></div><div><strong>2</strong><span>Active accounts</span></div><div><strong>Protected</strong><span>By Asterius</span></div></div></section>; }
function Accounts() { const [data, setData] = useState(); useEffect(() => { fetch(`${api}/api/accounts`, { credentials: 'include' }).then(r => r.json()).then(setData); }, []); return <Panel title="Accounts">{data?.error ? <Login /> : data ? <div className="account-grid">{data.accounts.map(a => <article className="account" key={a.id}><span>{a.name}</span><strong>{a.currency} {a.balance.toLocaleString(undefined, { minimumFractionDigits: 2 })}</strong><small>Available balance · {a.id}</small></article>)}</div> : <p>Loading…</p>}</Panel>; }
function Transfers() {
  const [data, setData] = useState();
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [pending, setPending] = useState(false);
  const [writeDenied, setWriteDenied] = useState(false);
  const [from, setFrom] = useState('checking');
  const [to, setTo] = useState('savings');
  const [amount, setAmount] = useState('');
  const [reference, setReference] = useState('');

  async function load() {
    const responses = await Promise.all(['accounts', 'transfers'].map(name => fetch(`${api}/api/${name}`, { credentials: 'include' })));
    if (responses.some(response => response.status === 401)) return { authenticated: false };
    if (responses.some(response => !response.ok)) throw new Error('Your account or transfer history could not be loaded. Check your read permission and try again.');
    const [accounts, transfers] = await Promise.all(responses.map(response => response.json()));
    if (!Array.isArray(accounts.accounts) || !Array.isArray(transfers.transfers)) throw new Error('The service returned an unexpected account or transfer response.');
    return { authenticated: true, accounts: accounts.accounts, transfers: transfers.transfers };
  }

  useEffect(() => {
    let active = true;
    load().then(result => { if (active) setData(result); }).catch(() => { if (active) setError('Your account or transfer history could not be loaded. Check your connection and read permission, then reload.'); });
    return () => { active = false; };
  }, []);

  async function submit(event) {
    event.preventDefault();
    if (pending || writeDenied) return;
    setError(''); setNotice('');
    const value = Number(amount);
    if (!Number.isFinite(value) || value <= 0 || from === to) {
      setError('Choose different accounts and a positive amount.');
      return;
    }
    setPending(true);
    try {
      const response = await fetch(`${api}/api/transfers`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ from, to, amount: value, reference }) });
      if (response.status === 401) { setData({ authenticated: false }); throw new Error('Your session is no longer active. Sign in before sending a transfer.'); }
      if (response.status === 403) { setWriteDenied(true); throw new Error('This session does not have permission to send transfers. Ask for accounts:write, then sign in again.'); }
      if (response.status === 400) throw new Error('The transfer was refused. Check the accounts, positive amount and available balance.');
      if (!response.ok) throw new Error('The service could not confirm the transfer. Check your history before trying again.');
      setNotice('Transfer recorded.'); setAmount(''); setReference('');
      try { setData(await load()); }
      catch { setError('The transfer was recorded, but the latest history could not be loaded. Reload before sending another transfer.'); setWriteDenied(true); }
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The transfer could not be confirmed. Check your history before trying again.');
    } finally { setPending(false); }
  }

  return <Panel title="Transfers">
    {error && <p className="form-error" role="alert">{error}</p>}
    {notice && <p className="form-notice" role="status">{notice}</p>}
    {data?.authenticated === false ? <Login /> : data?.authenticated ? <>
      <form className="transfer-form" onSubmit={submit}>
        <h2>Send a sample transfer</h2>
        <p>This changes the example ledger only. No real money moves.</p>
        <fieldset disabled={pending || writeDenied}>
          <div className="transfer-fields">
            <label>From account<select value={from} onChange={event => setFrom(event.target.value)} required>{data.accounts.map(account => <option key={account.id} value={account.id}>{account.name} ({account.currency})</option>)}</select></label>
            <label>To account<select value={to} onChange={event => setTo(event.target.value)} required>{data.accounts.map(account => <option key={account.id} value={account.id}>{account.name} ({account.currency})</option>)}</select></label>
            <label>Amount (EUR)<input type="number" min="0.01" step="0.01" value={amount} onChange={event => setAmount(event.target.value)} required /></label>
            <label>Reference (optional)<input type="text" maxLength={120} value={reference} onChange={event => setReference(event.target.value)} /></label>
          </div>
          <button type="submit">{pending ? 'Sending…' : 'Send sample transfer'}</button>
        </fieldset>
      </form>
      <h2>Transfer history</h2>
      {data.transfers.length ? data.transfers.map(transfer => <div className="transfer" key={transfer.id}><span>{transfer.from} → {transfer.to}{transfer.reference && <small>{transfer.reference}</small>}</span><strong>€{transfer.amount.toFixed(2)}</strong></div>) : <p>No transfers yet.</p>}
    </> : !error && <p>Loading…</p>}
  </Panel>;
}

function Panel({ title, children }) { return <section className="panel"><p className="eyebrow">NORTHSTAR FINANCIAL</p><h1>{title}</h1>{children}</section>; }
function Login() { return <p>You need to <a href={`${api}/auth/start`}>sign in with Asterius</a> first.</p>; }
createRoot(document.getElementById('root')).render(<BrowserRouter basename="/financial"><App /></BrowserRouter>);
