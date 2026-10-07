# Security review log

Findings from the 0.1 review and their resolution in 0.2.0. Details in `RELEASE_NOTES.md`.

| Finding | Severity | Status |
|---|---|---|
| Public attribute hash allowed single-component key recovery and policy bypass | Critical | Fixed (secret exponents, regression test) |
| Frontend download flow could not authenticate (token discarded) and used a wrong field | High | Fixed |
| Dev OTP mailbox enabled by default environment, unauthenticated | High | Endpoint removed, default production |
| OTP brute force through unlimited challenges, unsalted hash | High | Fixed (HMAC, lockouts, rate limits) |
| Slot burned before authorization, 500 on policy mismatch | Medium | Fixed |
| Plaintext temp files left after errors, no expiry sweep | Medium | Fixed |
| Upload limited to axum default 2 MiB | Medium | Fixed |
| Unbounded policy recursion (DoS) | Medium | Fixed |
| Unknown attributes accepted, UI/server mismatch | Medium | Fixed |
| No login/OTP rate limiting, user enumeration by timing | Medium | Mitigated |
| First-admin race, admin endpoint without CSRF/audit | Medium | Fixed |
| SMTP TLS mode mismatch with default port | Medium | Fixed |
| Weak master-key derivation, silent regeneration, 0644 file | Medium | Fixed |
| node_modules committed, broken .gitignore | Low | Fixed |
| Open registration without email verification, account enumeration via 409 | Low | Open (documented) |
| Not E2EE, no independent audit | Info | Open (documented) |
