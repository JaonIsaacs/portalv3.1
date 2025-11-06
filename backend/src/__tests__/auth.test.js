const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const createApp = require('../app');
const User = require('../models/User');
const RefreshToken = require('../models/RefreshToken');

let mongoServer;
let app;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  app = createApp();
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

afterEach(async () => {
  await User.deleteMany({});
  await RefreshToken.deleteMany({});
});

test('register -> login -> access protected route', async () => {
  /// register
  const reg = await request(app)
    .post('/api/auth/register')
    .send({ email: 'test@example.com', password: 'Password123!', name: "Tester" })
    .expect(201)

  expect(reg.body.email).toBe('test@example.com');

  /// login
  const login = await request(app)
    .post('/api/auth/login')
    .send({ email: 'test@example.com', password: 'Password123!' })
    .expect(200)

  /// extract cookie
  const cookies = login.headers['set-cookie'];
  expect(cookies).toBeDefined();

  /// access protected
  const p = await request(app)
    .get('/api/protected')
    .set('Cookie', cookies)
    .expect(200)

  expect(p.body.message).toBe('Protected data');
  expect(p.body.user).toBeDefined();
});

test('refresh token rotation and protected access', async () => {
  /// register
  await request(app).post('/api/auth/register').send({ email: 'rtest@example.com', password: 'Password123!', name: "RTester" }).expect(201)

  /// login
  const login = await request(app).post('/api/auth/login').send({ email: 'rtest@example.com', password: 'Password123!' }).expect(200)
  const cookies = login.headers['set-cookie'];
  expect(cookies).toBeDefined();

  /// simulate loss of access token by removing session cookie
  const refreshCookie = cookies.find(c => c.startsWith('refresh='));
  expect(refreshCookie).toBeDefined();
  const refreshVal = refreshCookie.split(';')[0].split('=')[1];

  /// call refresh endpoint with refresh cookie
  const refreshResp = await request(app).post('/api/auth/refresh').set('Cookie', [`refresh=${refreshVal}`]).expect(200)

  const newCookies = refreshResp.headers['set-cookie'];
  expect(newCookies).toBeDefined();

  const newSession = newCookies.find(c => c.startsWith('session='));
  expect(newSession).toBeDefined();

  /// use new session to access protected
  const p = await request(app).get('/api/protected').set('Cookie', [newSession]).expect(200)
  expect(p.body.message).toBe('Protected data');

  /// old refresh should be revoked: attempt to use old refresh value
  await request(app).post('/api/auth/refresh').set('Cookie', [`refresh=${refreshVal}`]).expect(401)
});
