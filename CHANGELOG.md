# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-11

### Added
- **Foundational Architecture**: Pydantic Settings configuration, SQLite WAL mode database engine with transactional connection pooling.
- **Argon2id & TOTP MFA**: Calibrated Argon2id password hashing, RFC 6238 TOTP two-factor authentication, and secure QR provisioning URI.
- **JWT & Refresh Token Rotation**: Ephemeral HS256 JWT access tokens, opaque refresh tokens with SHA-256 storage hashes, family tracking, and automatic revocation upon reuse detection.
- **Hybrid RBAC/ABAC Policy Decision Point (PDP)**: Unified authorization engine evaluating role hierarchy entitlements alongside contextual attributes (IP/CIDR, temporal hour windows, tenant boundary, resource ownership).
- **Cryptographic Audit Ledger**: Sequential SHA-256 hash chaining across all audit records (`AuditLogEntry`) with mathematical tamper-detection verification.
- **Security Middleware**: Sliding-window rate limiter with exponential backoff lockout and OWASP defense-in-depth security response headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
- **FastAPI REST API**: Comprehensive endpoints for `/auth` (login, mfa-verify, refresh, logout, me), `/users` (CRUD), `/roles` (manage, assign, revoke), `/resources` (reports, documents with ownership check), and `/audit` (entries, verify).
- **Typer CLI Administration Suite**: `rbac-admin` command-line utility featuring `bootstrap`, `users-list`, `user-create`, `user-lock`, `audit-verify`, and `simulate-policy`.
- **Adversarial & Security Testbed**: Brute-force lockout tests, JWT token forgery tests, and rate-limiting DDoS mitigation verification.
- **Production Containerization & CI**: Multi-stage rootless Dockerfile (UID 10001), Docker Compose file, and GitHub Actions CI workflow.
