const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const cors = require('cors');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');

const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

function createApp() {
  const app = express();
  // If running behind a proxy/load balancer (e.g., Heroku, nginx), enable trust proxy so
  // secure cookies and req.protocol work correctly when TLS is terminated upstream.
  if (process.env.TRUST_PROXY === 'true' || process.env.NODE_ENV === 'production') {
    app.set('trust proxy', 1);
  }

  /// Basic security middleware
  app.use(helmet());
  // Add a conservative Content Security Policy (report-only by default).
  // Adjust directives for your frontend as needed; in production you may want to switch reportOnly to false.
  app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
    reportOnly: process.env.CSP_REPORT_ONLY !== 'false'
  }));
  // Enforce HSTS in production
  if (process.env.NODE_ENV === 'production') {
    app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
  }
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(xss());
  app.use(mongoSanitize());
  app.use(hpp());

  // Configure CORS for frontend
  const defaultOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
  app.use(cors({ 
    origin: defaultOrigin, 
    credentials: true,
    methods: ['GET','POST','PUT','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization','csrf-token']
  }));

  // Configure CSP to allow frontend connection
  app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'", defaultOrigin],
      frameAncestors: ["'none'"],
    }
  }));

  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
  app.use(limiter);

  // Enable CSRF in non-test environments
  if (process.env.NODE_ENV !== 'test') {
    app.use(csurf({ cookie: true }));
    app.get('/csrf-token', (req, res) => res.json({ csrfToken: req.csrfToken() }));
    // Provide CSRF token under API auth path too for frontend convenience
    app.get('/api/auth/csrf-token', (req, res) => res.json({ csrfToken: req.csrfToken() }));
  }

  // Redirect HTTP to HTTPS when in production and behind a proxy
  if (process.env.NODE_ENV === 'production' && process.env.FORCE_HTTPS === 'true') {
    app.use((req, res, next) => {
      if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
      const host = req.headers.host;
      return res.redirect(301, `https://${host}${req.originalUrl}`);
    });
  }

  app.use('/api/auth', authRoutes);
  app.use('/api/protected', protectedRoutes);

  // Error handler for CSRF
  app.use((err, req, res, next) => {
    if (err && err.code === 'EBADCSRFTOKEN') return res.status(403).json({ error: 'Invalid CSRF token' });
    next(err);
  });

  return app;
}

module.exports = createApp;
