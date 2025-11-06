# Backend (Express + MongoDB)

Setup:

1. Copy `.env.example` to `.env` and set `JWT_SECRET` and `MONGO_URI`.
2. Install dependencies: run `npm install` in the `backend` folder.
3. (Optional for HTTPS dev) Generate self-signed certs and place them in `backend/cert/` as `key.pem` and `cert.pem`.

Generating a self-signed cert on Windows PowerShell (developer-only):

```powershell
mkdir cert; 
cd cert; 
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Org/OU=Dev/CN=localhost"
```

Security features included:

- bcrypt hashing with salt rounds (12)
- Input whitelisting via regex in `src/middleware/validate.js`
- Helmet for secure headers
- Rate limiting
- CSRF protection using `csurf` + cookie
- XSS cleaning and MongoDB query sanitization
- Secure cookie flags for session token

Notes and production tips:

- Always run behind a proper HTTPS reverse proxy (Nginx, cloud load balancer) with valid CA certs.
- Use a strong JWT secret and rotate keys. Consider using short-lived access tokens and refresh tokens.
- Harden CORS origin to your frontend domain in production.
- Use a secure session store if you need server-side sessions.
 - Use a secure session store if you need server-side sessions.

Admin provisioning
------------------

To create users (self-registration is disabled), use the provided provisioning script:

```powershell
cd backend
node scripts/create_user.js --email "alice@example.com" --name "Alice" --password "StrongPass123!"
```

The script reads `MONGO_URI` from the environment or defaults to a local MongoDB instance.
