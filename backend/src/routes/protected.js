const express = require('express');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const router = express.Router();

function authMiddleware(req, res, next) {
  const token = req.cookies && req.cookies.session;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret');
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

router.get('/', authMiddleware, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});

module.exports = router;
