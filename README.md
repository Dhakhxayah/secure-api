# Secure API — Production-Grade Backend in Rust

A secure REST API backend built with Rust, implementing 18 real-world security features across 8 defense layers.

## Security Features
- JWT Authentication with token blacklisting on logout
- Argon2 password hashing
- Endpoint-specific rate limiting (login: 5/min, general: 60/min)
- Brute force protection (account locks after 5 failed attempts)
- Secure HTTP headers (CSP, HSTS, X-Frame-Options, etc.)
- CORS policy
- SQL injection prevention via parameterized queries
- Least privilege database user
- Audit logging for every action
- 11 passing unit tests

## Tech Stack
- **Language:** Rust
- **Web Framework:** Axum
- **Database:** PostgreSQL + sqlx
- **Cache:** Redis
- **Auth:** JWT (jsonwebtoken)
- **Password Hashing:** Argon2
- **Logging:** tracing

## API Endpoints
| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | /health | No | Health check |
| POST | /auth/register | No | Create account |
| POST | /auth/login | No | Login, get JWT |
| GET | /auth/me | Yes | Get profile |
| POST | /auth/logout | Yes | Logout, blacklist token |

## Setup

### Requirements
- Rust
- PostgreSQL
- Redis

### Run
```bash
cp .env.example .env
# Edit .env with your database credentials
cargo run
```

### Test
```bash
cargo test
```
