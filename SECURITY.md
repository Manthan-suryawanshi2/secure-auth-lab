# Security Notes

This project is a local learning demo, not a production-ready identity service.

## Controls in this demo

- **Password hashing:** Passwords are hashed with bcryptjs using a cost factor of 12. The database stores only the hash.
- **Server-side validation:** Zod validates and normalizes usernames and validates password length and UTF-8 byte length on every registration and login request.
- **Generic login errors:** Unknown usernames and incorrect passwords receive the same status and message. Login performs bcrypt comparison against either the account hash or a precomputed dummy hash, reducing the timing difference for unknown accounts. Network timing cannot be made perfectly constant.
- **Session cookies:** The session cookie is HTTP-only and SameSite=Lax. It is Secure in production and expires after 30 minutes.
- **Session contents:** Only the authenticated user's ID is stored in the session. The session ID is regenerated after login.
- **Login rate limiting:** Failed login attempts are limited to five per client IP per 15 minutes. Successful requests do not consume the failure allowance.
- **Parameterized SQL:** All values used in database queries are passed as parameters rather than concatenated into SQL strings.

These controls help reduce password disclosure from a database leak, basic injection, malformed-input, account enumeration, session theft through browser scripts, session fixation, and repeated password-guessing risks.

## Limitations

- Express's default in-memory session store is intended only for local development. It loses sessions when the process restarts and is not appropriate for production or multiple server instances.
- The default SQLite database is a local file. It has no backups, encryption-at-rest, account recovery, or operational monitoring.
- IP-based rate limiting is in memory, resets on restart, and can be bypassed or cause shared-network users to affect one another. A production deployment needs a shared rate-limit store and careful proxy configuration.
- This demo does not include CSRF protection, email verification, password reset, multi-factor authentication, account lockout policy, audit logging, or security headers beyond hiding Express's identifying header.
- In production, provide a strong unique `SESSION_SECRET`, use HTTPS, configure trusted proxies deliberately if applicable, and replace the session store. Do not deploy this demo as-is.