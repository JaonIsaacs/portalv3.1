#!/usr/bin/env node
/// Simple provisioning script to create a user from the command line.
/// Usage: node scripts/create_user.js has been changed fortest purpes (see readme)

const https = require('https');
const crypto = require('crypto');
const mongoose = require('mongoose');
const User = require('../src/models/User');
require('dotenv').config();

function sha1(str) {
  return crypto.createHash('sha1').update(str).digest('hex').toUpperCase();
}

function queryPwnedApi(prefix) {
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'portalv3.1' } }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

async function isPwnedPassword(password) {
  const hash = sha1(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const body = await queryPwnedApi(prefix);
  const lines = body.split('\n');
  for (const line of lines) {
    const [h, countStr] = line.split(':');
    if (!h) continue;
    if (h.trim() === suffix) {
      const count = parseInt(countStr, 10) || 0;
      return count > 0;
    }
  }
  return false;
}

async function main() {
  const argv = require('yargs/yargs')(process.argv.slice(2)).options({
    email: { type: 'string', demandOption: true },
    name: { type: 'string', demandOption: true },
    password: { type: 'string', demandOption: true }
  }).argv;

  // Check password against HaveIBeenPwned
  try {
    const pwned = await isPwnedPassword(argv.password);
    if (pwned) {
      console.error('Refusing to use a known-breached password. Choose a different password.');
      process.exit(2);
    }
  } catch (err) {
    console.warn('Could not check password against HIBP API. Proceeding without check.', err.message || err);
  }

  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/portal';
  await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  const hash = await User.hashPassword(argv.password);
  const u = await User.create({ email: argv.email, name: argv.name, passwordHash: hash });
  console.log('Created user:', u.email, u._id.toString());
  await mongoose.disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
