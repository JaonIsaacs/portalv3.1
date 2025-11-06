const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const { validateLogin } = require('../middleware/validate');
require('dotenv').config();

const RefreshToken = require('../models/RefreshToken');

const router = express.Router();

function generateAccessToken(user) {
  return jwt.sign({ sub: user._id, email: user.email }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: process.env.ACCESS_TOKEN_EXPIRES || '15m' });
}

const bcrypt = require('bcrypt');
const REFRESH_TOKEN_SECRET_BYTES = 40;
const TOKEN_ID_BYTES = 16;
const SALT_ROUNDS = 12;

// Registration is disabled: users must be created by an administrator or provisioning process.
// This protects the system from uncontrolled self-registration.
router.post('/register', (req, res) => {
  console.warn('Attempted registration while registration is disabled:', req.ip);
  return res.status(403).json({ error: 'Registration is disabled' });
});

// Login
// Apply a more strict per-route rate limit for login to mitigate brute force
const loginLimiter = require('express-rate-limit')({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
router.post('/login', loginLimiter, validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    // Check lockout
    if (user.isLocked && user.isLocked()) return res.status(423).json({ error: 'Account locked. Try later.' });

    const ok = await user.verifyPassword(password);
    if (!ok) {
      await user.incFailedLogin();
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Successful login: reset failure counter
    await user.resetFailedLogins();

    // Create JWT 
    const accessToken = generateAccessToken(user);

  // create refresh token as tokenId.secret and store only hash of secret
  const tokenId = require('crypto').randomBytes(TOKEN_ID_BYTES).toString('hex');
  const secret = require('crypto').randomBytes(REFRESH_TOKEN_SECRET_BYTES).toString('hex');
  const refreshToken = `${tokenId}.${secret}`;
  const expires = new Date(Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_SECONDS || '604800') * 1000)); /// default 7 days
  const hash = await bcrypt.hash(secret, SALT_ROUNDS);
  await RefreshToken.create({ tokenId, tokenHash: hash, user: user._id, expiresAt: expires });

  /// Set cookies: access token and refresh token (HttpOnly)
  res.cookie('session', accessToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
  res.cookie('refresh', refreshToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
    res.json({ message: 'Logged in' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Logout - clear cookie and revoke refresh token if present
router.post('/logout', async (req, res) => {
  try {
    const r = req.cookies && req.cookies.refresh;
    if (r) {
      // refresh token format is tokenId.secret
      const parts = r.split('.');
      const tokenId = parts[0];
      if (tokenId) {
        await RefreshToken.findOneAndUpdate({ tokenId }, { revoked: true });
      }
    }
  } catch (e) { console.error(e); }
  res.clearCookie('session', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
  res.clearCookie('refresh', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
  res.json({ message: 'Logged out' });
});

/// Token refresh - rotate refresh tokens
router.post('/refresh', async (req, res) => {
  try {
  const token = req.cookies && req.cookies.refresh;
  if (!token) return res.status(401).json({ error: 'No refresh token' });

  const parts = token.split('.');
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid refresh token format' });
  const [tokenId, secret] = parts;

  const stored = await RefreshToken.findOne({ tokenId });
  if (!stored || stored.revoked || stored.expiresAt < new Date()) return res.status(401).json({ error: 'Invalid refresh token' });

  const ok = await bcrypt.compare(secret, stored.tokenHash);
  if (!ok) return res.status(401).json({ error: 'Invalid refresh token' });

  const user = await User.findById(stored.user);
  if (!user) return res.status(401).json({ error: 'Invalid refresh token' });

  // rotate refresh token: create new tokenId.secret and revoke old
  const newTokenId = require('crypto').randomBytes(TOKEN_ID_BYTES).toString('hex');
  const newSecret = require('crypto').randomBytes(REFRESH_TOKEN_SECRET_BYTES).toString('hex');
  const newRefreshToken = `${newTokenId}.${newSecret}`;
  const expires = new Date(Date.now() + (parseInt(process.env.REFRESH_TOKEN_EXPIRES_SECONDS || '604800') * 1000));

  stored.revoked = true;
  stored.replacedByToken = newTokenId;
  await stored.save();

  const newHash = await bcrypt.hash(newSecret, SALT_ROUNDS);
  await RefreshToken.create({ tokenId: newTokenId, tokenHash: newHash, user: user._id, expiresAt: expires });

  const accessToken = generateAccessToken(user);

  res.cookie('session', accessToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
  res.cookie('refresh', newRefreshToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict' });
  res.json({ message: 'Refreshed' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
