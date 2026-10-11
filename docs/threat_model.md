# STRIDE Threat Model — RBAC/ABAC Zero Trust Security REST API

## 1. Overview
This threat model assesses the threat surface, vulnerabilities, and mitigations implemented within the RBAC Secure REST API service using Microsoft's **STRIDE** methodology.

---

## 2. Threat Analysis Matrix

| Threat Category | Potential Attack Vector | Impact | Mitigations Implemented |
|---|---|---|---|
| **Spoofing** | • Forged JWT authentication tokens<br>• Stolen user credentials<br>• Replay of refresh tokens | Unauthorized identity assumption and data exposure | • Cryptographically signed HS256 JWT tokens with `sub`, `exp`, `iat`, `jti`<br>• Argon2id password hashing with salt and calibrated memory cost<br>• Single-use Refresh Token Rotation with immediate family revocation upon reuse detection<br>• TOTP Multi-Factor Authentication (RFC 6238) |
| **Tampering** | • Direct modification of database audit records<br>• Manipulation of role permissions in transit | Cover up attacker tracks, unauthorized privilege granting | • Cryptographic SHA-256 sequential hash chaining across all audit records (`previous_hash` linking)<br>• Automated hash chain integrity verifier detecting payload alteration and chain severance<br>• Parameterized SQLite queries (`?` bindings) preventing SQL Injection |
| **Repudiation** | • Disputing privileged actions executed by admin accounts | Lack of legal/forensic attribution for security incidents | • Immutable append-only audit ledger recording `user_id`, `role`, `action`, `resource`, `decision`, `ip_address`, `user_agent`<br>• Mathematical integrity verification proving records were not altered post-facto |
| **Information Disclosure** | • Sensitive password hashes or MFA secrets leaked via API<br>• Clickjacking or MIME type sniffing | Compromised user secrets and customer breach | • Strict output filtering via `UserResponse` Pydantic models (omits `password_hash` and `mfa_secret`)<br>• OWASP security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Content-Security-Policy` |
| **Denial of Service** | • Credential brute-force attacks<br>• API flooding and resource starvation | Service degradation or offline downtime | • Sliding-window in-memory rate limiter per IP/user<br>• Exponential backoff lockout for persistent rate-limit violators<br>• Account lockout after 5 consecutive failed login attempts |
| **Elevation of Privilege** | • BOLA / IDOR attacks accessing other tenant resources<br>• Role hierarchy privilege escalation | Unauthorized horizontal or vertical privilege escalation | • Hybrid Policy Decision Point (PDP) combining strict RBAC permissions with contextual ABAC rules<br>• Mandatory tenant match and resource ownership verification preventing cross-tenant access |
