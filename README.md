# Secure Authentication Lab

A small local Node.js service for learning defensive authentication. It includes registration, login, logout, a protected user endpoint, and automated security tests.

## Prerequisites

- Node.js 20 or newer
- npm (included with Node.js)

## Install and run

```powershell
npm install
Copy-Item .env.example .env
```

Set a private session secret in `.env` before starting. For local development, any long random value will work. Then run:

```powershell
npm start
```

The service listens on `http://localhost:3000`. SQLite creates `auth.db` in the project directory on first start. The `.env` and database file are ignored by Git.

## Run tests

```powershell
npm test
```

Tests use a fresh in-memory SQLite database, so they do not alter your development database. A passing run reports 10 tests passed.

## API

Send JSON requests with `Content-Type: application/json`. Usernames are trimmed, 3-30 characters, and may contain only letters, numbers, and underscores. Passwords must be 12-72 characters and at most 72 UTF-8 bytes.

### `POST /register`

```json
{
  "username": "alex_01",
  "password": "correct horse battery staple"
}
```

Creates a user and responds with HTTP 201. Existing usernames return HTTP 409; invalid input returns HTTP 400.

### `POST /login`

Send the same JSON shape as registration. On success, responds with HTTP 200 and sets the session cookie. A wrong password or unknown username responds with HTTP 401 and the same generic error. Failed attempts are rate limited.

### `GET /me`

Returns the logged-in user's ID and username. Requires the session cookie; otherwise responds with HTTP 401.

### `POST /logout`

Destroys the current session and clears its cookie.

## Security features

Passwords are hashed with bcryptjs (cost factor 12), credentials are validated on the server with Zod, and SQL queries are parameterized. Sessions use HTTP-only, SameSite=Lax cookies with a 30-minute expiration and Secure cookies in production. See [SECURITY.md](SECURITY.md) for the protections and demo limitations.