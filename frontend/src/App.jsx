import React, { useState } from 'react'

// Use Vite env API (import.meta.env) instead of process.env
const API_BASE = import.meta.env.MODE === 'production' ? 'https://api.example.com' : 'http://localhost:4000';

const getCsrf = async () => {
  try {
    const t = await fetch(`${API_BASE}/api/auth/csrf-token`, { credentials: 'include' });
    const j = await t.json();
    return j.csrfToken;
  } catch (e) {
    console.error('CSRF token fetch failed:', e);
    return null;
  }
}

const API = async (path, opts = {}) => {
  const doFetch = () => {
    // Split out headers so we don't accidentally overwrite the merged headers when spreading opts
    const { headers: optHeaders = {}, ...rest } = opts || {};
    const headers = { 'Content-Type': 'application/json', ...optHeaders };
    // Remove any leading slashes to avoid double slashes
    const cleanPath = path.startsWith('/') ? path.slice(1) : path;
    return fetch(`${API_BASE}/${cleanPath}`, { credentials: 'include', headers, ...rest });
  };

  let res = await doFetch();

  /// If unauthorized attempt to refresh and retry once
  if (res.status === 401) {
    const csrf = await getCsrf();
    const refreshRes = await fetch(`${API_BASE}/api/auth/refresh`, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', ...(csrf ? { 'csrf-token': csrf } : {}) } });
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

function Register() {
  // Registration disabled: show explanatory message
  return (
    <div>
      <h3>Registration Disabled</h3>
      <p>New user registration is disabled. Contact an administrator to create an account.</p>
    </div>
  )
}
/// Login component
function Login({ onMessage }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const submit = async e => {
    e.preventDefault()
    if (!patterns.email.test(email)) return onMessage('Invalid email')
    if (!patterns.password.test(password)) return onMessage('Invalid password')

    try {
      console.log('Fetching CSRF token...');
      const token = await API('/api/auth/csrf-token')
      console.log('Got CSRF token:', token);
      
      console.log('Attempting login...');
      await API('/api/auth/login', { 
        method: 'POST', 
        body: JSON.stringify({ email, password }), 
        headers: { 'csrf-token': token.csrfToken } 
      })
      console.log('Login successful');
      onMessage('Logged in')
    } catch (err) {
      console.error('Login error:', err);
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
/// main app
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
