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

  /// Basic security middleware
  app.use(helmet());
  app.use(express.json({ limit: '10kb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use(cookieParser());
  app.use(xss());
  app.use(mongoSanitize());
  app.use(hpp());

  const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false });
  app.use(limiter);

  const defaultOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';
  app.use(cors({ origin: defaultOrigin, credentials: true }));

  // Enable CSRF in non-test environments
  if (process.env.NODE_ENV !== 'test') {
    app.use(csurf({ cookie: true }));
    app.get('/csrf-token', (req, res) => res.json({ csrfToken: req.csrfToken() }));
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
