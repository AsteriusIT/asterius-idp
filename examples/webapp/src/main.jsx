import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import './style.css';

const api = import.meta.env.VITE_API_URL || '/financial-api';
function App() {
  const [session, setSession] = useState(null);
  useEffect(() => { fetch(`${api}/api/session`, { credentials: 'include' }).then(r => r.json()).then(setSession); }, []);
  return <div className="shell"><header><Link to="/" className="brand">Northstar <span>Financial</span></Link><nav><Link to="/accounts">Accounts</Link><Link to="/transfers">Transfers</Link></nav>{session?.authenticated ? <button onClick={async () => { await fetch(`${api}/auth/logout`, { method: 'POST', credentials: 'include' }); location.reload(); }}>Sign out</button> : <a className="button" href={`${api}/auth/start`}>Sign in with Asterius</a>}</header><main><Routes><Route path="/" element={<Home authenticated={session?.authenticated} />} /><Route path="/accounts" element={<Accounts />} /><Route path="/transfers" element={<Transfers />} /></Routes></main></div>;
}
function Home({ authenticated }) { return <section className="hero"><p className="eyebrow">PRIVATE WEALTH · SECURE BY DESIGN</p><h1>Your money,<br /><em>in clear view.</em></h1><p className="lead">A small financial API protected by Asterius FAPI security controls: PAR, PKCE, private_key_jwt and DPoP.</p>{authenticated ? <Link className="button" to="/accounts">View your accounts</Link> : <a className="button" href={`${api}/auth/start`}>Open your secure workspace</a>}<div className="cards"><div><strong>€17,050.75</strong><span>Total balance</span></div><div><strong>2</strong><span>Active accounts</span></div><div><strong>Protected</strong><span>By Asterius</span></div></div></section>; }
function Accounts() { const [data, setData] = useState(); useEffect(() => { fetch(`${api}/api/accounts`, { credentials: 'include' }).then(r => r.json()).then(setData); }, []); return <Panel title="Accounts">{data?.error ? <Login /> : data ? <div className="account-grid">{data.accounts.map(a => <article className="account" key={a.id}><span>{a.name}</span><strong>{a.currency} {a.balance.toLocaleString(undefined, { minimumFractionDigits: 2 })}</strong><small>Available balance · {a.id}</small></article>)}</div> : <p>Loading…</p>}</Panel>; }
function Transfers() { const [data, setData] = useState(); useEffect(() => { fetch(`${api}/api/transfers`, { credentials: 'include' }).then(r => r.json()).then(setData); }, []); return <Panel title="Transfers">{data?.error ? <Login /> : data ? data.transfers.length ? data.transfers.map(t => <div className="transfer" key={t.id}><span>{t.from} → {t.to}</span><strong>€{t.amount.toFixed(2)}</strong></div>) : <p>No transfers yet.</p> : <p>Loading…</p>}</Panel>; }
function Panel({ title, children }) { return <section className="panel"><p className="eyebrow">NORTHSTAR FINANCIAL</p><h1>{title}</h1>{children}</section>; }
function Login() { return <p>You need to <a href={`${api}/auth/start`}>sign in with Asterius</a> first.</p>; }
createRoot(document.getElementById('root')).render(<BrowserRouter basename="/financial"><App /></BrowserRouter>);
