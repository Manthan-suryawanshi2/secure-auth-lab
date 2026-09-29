require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');
const { z } = require('zod');
const db = require('./db');

const BCRYPT_COST = 12;
const DUMMY_PASSWORD_HASH = '$2b$12$e4zkdx.UgTy2xI1o75uoI.UaRFuaossJyAC.MDYwQTcQOEyZcVbTG';
const SESSION_MAX_AGE = 30 * 60 * 1000;
const USERNAME_PATTERN = /^[A-Za-z0-9_]+$/;
const credentialsSchema = z.object({
  username: z.string().trim().min(3).max(30).regex(USERNAME_PATTERN),
  password: z.string().min(12).max(72).refine(
    (password) => Buffer.byteLength(password, 'utf8') <= 72,
  ),
}).strict();

function createApp({ database = db, loginLimitMax = 5 } = {}) {
  const app = express();
  const isProduction = process.env.NODE_ENV === 'production';
  const sessionSecret = process.env.SESSION_SECRET;

  if (!sessionSecret) {
    throw new Error('SESSION_SECRET must be set in the environment');
  }

  app.disable('x-powered-by');
  app.use(express.json({ limit: '10kb' }));
  app.use(session({
    name: 'auth.sid',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProduction,
      maxAge: SESSION_MAX_AGE,
    },
  }));

  const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: loginLimitMax,
    skipSuccessfulRequests: true,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: 'Too many login attempts. Please try again later.' },
  });

  app.post('/register', async (req, res) => {
    const parsed = credentialsSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const { username, password } = parsed.data;
    const existingUser = database.prepare(
      'SELECT id FROM users WHERE username = ?',
    ).get(username);
    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    try {
      const passwordHash = await bcrypt.hash(password, BCRYPT_COST);
      const result = database.prepare(
        'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      ).run(username, passwordHash);

      return res.status(201).json({
        message: 'Registration successful',
        user: { id: Number(result.lastInsertRowid), username },
      });
    } catch (error) {
      if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        return res.status(409).json({ error: 'Username already exists' });
      }
      return res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/login', loginLimiter, async (req, res) => {
    const parsed = credentialsSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid input' });
    }

    const { username, password } = parsed.data;
    const user = database.prepare(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
    ).get(username);

    const passwordHash = user ? user.password_hash : DUMMY_PASSWORD_HASH;
    const passwordMatches = await bcrypt.compare(password, passwordHash);
    if (!user || !passwordMatches) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    req.session.regenerate((error) => {
      if (error) {
        return res.status(500).json({ error: 'Internal server error' });
      }

      req.session.userId = user.id;
      return req.session.save((saveError) => {
        if (saveError) {
          return res.status(500).json({ error: 'Internal server error' });
        }
        return res.status(200).json({
          message: 'Login successful',
          user: { id: user.id, username: user.username },
        });
      });
    });
  });

  app.post('/logout', (req, res) => {
    req.session.destroy((error) => {
      if (error) {
        return res.status(500).json({ error: 'Internal server error' });
      }

      res.clearCookie('auth.sid', {
        httpOnly: true,
        sameSite: 'lax',
        secure: isProduction,
      });
      return res.status(200).json({ message: 'Logout successful' });
    });
  });

  app.get('/me', (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const user = database.prepare(
      'SELECT id, username FROM users WHERE id = ?',
    ).get(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    return res.status(200).json({ user });
  });

  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({ error: 'Invalid JSON' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

if (require.main === module) {
  const app = createApp();
  const port = Number(process.env.PORT) || 3000;
  app.listen(port, () => {
    console.log(`Secure Authentication Lab listening on port ${port}`);
  });
}

module.exports = { createApp };