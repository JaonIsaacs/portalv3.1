#!/usr/bin/env node
// Create a user without HaveIBeenPwned check (for local dev/testing only)
const mongoose = require('mongoose');
const User = require('../src/models/User');
const argv = require('yargs/yargs')(process.argv.slice(2)).options({
  email: { type: 'string', demandOption: true },
  name: { type: 'string', demandOption: true },
  password: { type: 'string', demandOption: true }
}).argv;

async function main(){
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/portal';
  await mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  const hash = await User.hashPassword(argv.password);
  const existing = await User.findOne({ email: argv.email.toLowerCase() });
  if (existing) {
    console.log('User already exists:', existing.email);
  } else {
    const u = await User.create({ email: argv.email, name: argv.name, passwordHash: hash });
    console.log('Created user:', u.email, u._id.toString());
  }
  await mongoose.disconnect();
}

main().catch(err => { console.error(err); process.exit(1); });
