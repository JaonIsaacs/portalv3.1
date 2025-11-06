const fs = require('fs');
const path = require('path');
const https = require('https');
const mongoose = require('mongoose');
require('dotenv').config();

const createApp = require('./app');

const PORT = process.env.PORT || 4000;
let MONGO_URI = process.env.MONGO_URI;

async function start() {
  let mongod;
  try {
    if (!MONGO_URI && process.env.NODE_ENV !== 'production') {
      // start in-memory mongo for local development when no MONGO_URI provided
      console.log('No MONGO_URI provided. Starting in-memory MongoDB for development...');
      const { MongoMemoryServer } = require('mongodb-memory-server');
      mongod = await MongoMemoryServer.create();
      MONGO_URI = mongod.getUri();
    }

    await mongoose.connect(MONGO_URI || 'mongodb://localhost:27017/portal', { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to MongoDB');

    const app = createApp();

    
    const keyPath = process.env.SSL_KEY || path.join(__dirname, '..', 'cert', 'key.pem');
    const certPath = process.env.SSL_CERT || path.join(__dirname, '..', 'cert', 'cert.pem');

    if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
      const options = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
      https.createServer(options, app).listen(PORT, () => {
        console.log(`HTTPS server listening on https://localhost:${PORT}`);
      });
    } else {
      app.listen(PORT, () => {
        console.log(`HTTP server listening on http://localhost:${PORT} (no SSL certs found)`);
      });
    }
  } catch (err) {
    console.error('MongoDB connection error', err);
    if (mongod) await mongod.stop();
    process.exit(1);
  }
}

start();
