import React, { useState } from 'react'

const API_BASE = 'http://localhost:4000';

const getCsrf = async () => {
  try {
    const t = await fetch(`${API_BASE}/csrf-token`, { credentials: 'include' });
    const j = await t.json();
    return j.csrfToken;
  } catch (e) {
    return null;
  }
}

const API = async (path, opts = {}) => {
  const defaultHeaders = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const doFetch = () => {
    // avoid letting opts override headers set above
    const { headers, ...rest } = opts || {};
    return fetch(API_BASE + path, { credentials: 'include', headers: defaultHeaders, ...rest });
  };

  let res = await doFetch();

  // If unauthorized, attempt to refresh and retry once
  if (res.status === 401) {
    const csrf = await getCsrf();
    const refreshRes = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', ...(csrf ? { 'csrf-token': csrf } : {}) } });
    if (refreshRes.ok) {
      res = await doFetch();
    } else {
      const err = await res.json().catch(() => null);
      throw err || { error: 'Unauthorized' };
    }
  }

  const json = await res.json().catch(() => null);
  if (!res.ok) throw json || { error: 'Network error' };
  return json;
}

const patterns = {
  email: /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/, 
  password: /^[A-Za-z0-9!@#$%^&*()_+=[\]{}|;:'",.<>/?`~\\-]{8,128}$/,
  name: /^[A-Za-z \-']{1,100}$/
}

function Register({ onMessage }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')

  const submit = async e => {
    e.preventDefault()
    if (!patterns.email.test(email)) return onMessage('Invalid email')
    if (!patterns.password.test(password)) return onMessage('Invalid password')
    if (!patterns.name.test(name)) return onMessage('Invalid name')

    // fetch CSRF token then register
    const token = await API('/csrf-token')
    try {
      await API('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password, name }), headers: { 'csrf-token': token.csrfToken } })
      onMessage('Registered')
    } catch (err) {
      onMessage(err.error || 'Error')
    }
  }

  return (
    <form onSubmit={submit}>
      <h3>Register</h3>
      <input placeholder="Name" value={name} onChange={e => setName(e.target.value)} />
      <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button type="submit">Register</button>
    </form>
  )
}

function Login({ onMessage }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const submit = async e => {
    e.preventDefault()
    if (!patterns.email.test(email)) return onMessage('Invalid email')
    if (!patterns.password.test(password)) return onMessage('Invalid password')

    const token = await API('/csrf-token')
    try {
      await API('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }), headers: { 'csrf-token': token.csrfToken } })
      onMessage('Logged in')
    } catch (err) {
      onMessage(err.error || 'Error')
    }
  }

  return (
    <form onSubmit={submit}>
      <h3>Login</h3>
      <input placeholder="Email" value={email} onChange={e => setEmail(e.target.value)} />
      <input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
      <button type="submit">Login</button>
    </form>
  )
}

export default function App() {
  const [page, setPage] = useState('login')
  const [msg, setMsg] = useState('')
  const [user, setUser] = useState(null)

  const fetchProtected = async () => {
    try {
      const res = await API('/api/protected')
      setUser(res.user)
      setMsg('Fetched protected data')
    } catch (err) {
      setMsg(err.error || 'Error fetching protected data')
    }
  }

  const logout = async () => {
    const token = await API('/csrf-token')
    try {
      await API('/api/auth/logout', { method: 'POST', headers: { 'csrf-token': token.csrfToken } })
      setUser(null)
      setMsg('Logged out')
      setPage('login')
    } catch (err) {
      setMsg(err.error || 'Error during logout')
    }
  }

  return (
    <div style={{ padding: 20 }}>
      <nav>
        <button onClick={() => setPage('login')}>Login</button>
        <button onClick={() => setPage('register')}>Register</button>
        <button onClick={() => { setPage('dashboard'); fetchProtected(); }}>Dashboard</button>
        <button onClick={logout}>Logout</button>
      </nav>
      <p>{msg}</p>
      {page === 'register' && <Register onMessage={setMsg} />}
      {page === 'login' && <Login onMessage={setMsg} />}
      {page === 'dashboard' && <div><h3>Protected Dashboard</h3>{user ? <pre>{JSON.stringify(user, null, 2)}</pre> : <p>Not authenticated</p>}</div>}
    </div>
  )
}
