process.env.NODE_ENV = 'test';
process.env.SESSION_SECRET = 'test-only-session-secret-for-isolated-tests';
process.env.AUTH_DB_PATH = ':memory:';

const request = require('supertest');
const bcrypt = require('bcryptjs');
const db = require('../src/db');
const { createApp } = require('../src/server');

const app = createApp();
const validCredentials = {
  username: 'test_user',
  password: 'correct horse battery staple',
};

beforeEach(() => {
  db.exec('DELETE FROM users');
});

afterAll(() => {
  db.close();
});

describe('authentication security controls', () => {
  test('registers a user and never returns the password or hash', async () => {
    const response = await request(app).post('/register').send(validCredentials);

    expect(response.status).toBe(201);
    expect(response.body.user).toEqual({ id: 1, username: validCredentials.username });
    expect(JSON.stringify(response.body)).not.toContain(validCredentials.password);
    expect(response.body).not.toHaveProperty('password_hash');
  });

  test('rejects invalid registration input', async () => {
    const response = await request(app).post('/register').send({
      username: 'not valid!',
      password: 'short',
    });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: 'Invalid input' });
  });

  test.each(['/register', '/login'])(
    'returns HTTP 400 for malformed JSON on %s',
    async (endpoint) => {
      const response = await request(app)
        .post(endpoint)
        .set('Content-Type', 'application/json')
        .send('{bad json');

      expect(response.status).toBe(400);
      expect(response.body).toEqual({ error: 'Invalid JSON' });
    },
  );

  test('stores a bcrypt hash instead of the plaintext password', async () => {
    await request(app).post('/register').send(validCredentials);
    const stored = db.prepare(
      'SELECT password_hash FROM users WHERE username = ?',
    ).get(validCredentials.username);

    expect(stored.password_hash).not.toBe(validCredentials.password);
    expect(stored.password_hash).toMatch(/^\$2[aby]\$12\$/);
    await expect(bcrypt.compare(validCredentials.password, stored.password_hash))
      .resolves.toBe(true);
  });

  test('logs in with the correct password and returns no hash', async () => {
    await request(app).post('/register').send(validCredentials);
    const response = await request(app).post('/login').send(validCredentials);

    expect(response.status).toBe(200);
    expect(response.body.user.username).toBe(validCredentials.username);
    expect(response.body).not.toHaveProperty('password');
    expect(response.body).not.toHaveProperty('password_hash');
  });

  test('rejects an incorrect password', async () => {
    await request(app).post('/register').send(validCredentials);
    const response = await request(app).post('/login').send({
      ...validCredentials,
      password: 'incorrect password value',
    });

    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: 'Invalid username or password' });
  });

  test('uses the same generic error for unknown users and wrong passwords', async () => {
    await request(app).post('/register').send(validCredentials);
    const wrongPassword = await request(app).post('/login').send({
      ...validCredentials,
      password: 'incorrect password value',
    });
    const unknownUser = await request(app).post('/login').send({
      username: 'unknown_user',
      password: validCredentials.password,
    });

    expect(wrongPassword.status).toBe(unknownUser.status);
    expect(wrongPassword.body).toEqual(unknownUser.body);
  });

  test('performs bcrypt verification for existing and unknown usernames', async () => {
    await request(app).post('/register').send(validCredentials);
    const loginTestApp = createApp({ database: db });
    const stored = db.prepare(
      'SELECT password_hash FROM users WHERE username = ?',
    ).get(validCredentials.username);
    const compareSpy = jest.spyOn(bcrypt, 'compare');

    try {
      const existingUserResponse = await request(loginTestApp).post('/login').send({
        ...validCredentials,
        password: 'incorrect password value',
      });
      const unknownUserResponse = await request(loginTestApp).post('/login').send({
        username: 'unknown_user',
        password: validCredentials.password,
      });

      expect(existingUserResponse.status).toBe(401);
      expect(unknownUserResponse.status).toBe(401);
      expect(compareSpy).toHaveBeenCalledTimes(2);
      expect(compareSpy.mock.calls[0][1]).toBe(stored.password_hash);
      expect(compareSpy.mock.calls[1][1]).toMatch(/^\$2[aby]\$12\$/);
      expect(compareSpy.mock.calls[1][1]).not.toBe(stored.password_hash);
    } finally {
      compareSpy.mockRestore();
    }
  });

  test('/me requires authentication', async () => {
    const response = await request(app).get('/me');

    expect(response.status).toBe(401);
  });

  test('/me returns the current user after login', async () => {
    await request(app).post('/register').send(validCredentials);
    const agent = request.agent(app);
    await agent.post('/login').send(validCredentials);
    const response = await agent.get('/me');

    expect(response.status).toBe(200);
    expect(response.body.user.username).toBe(validCredentials.username);
    expect(response.body.user).not.toHaveProperty('password_hash');
  });

  test('logout destroys the session', async () => {
    await request(app).post('/register').send(validCredentials);
    const agent = request.agent(app);
    await agent.post('/login').send(validCredentials);
    const logoutResponse = await agent.post('/logout');
    const meResponse = await agent.get('/me');

    expect(logoutResponse.status).toBe(200);
    expect(meResponse.status).toBe(401);
  });

  test('rate limits repeated failed login attempts', async () => {
    const limitedApp = createApp({ loginLimitMax: 3 });
    const attempt = () => request(limitedApp).post('/login').send({
      username: 'unknown_user',
      password: validCredentials.password,
    });

    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    const blockedResponse = await attempt();

    expect(blockedResponse.status).toBe(429);
    expect(blockedResponse.body.error).toMatch(/Too many login attempts/);
  });
});