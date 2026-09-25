# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| v1.x    | ✅                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability, please:

1. **Do NOT open a public issue.**
2. Email the maintainers at the email on file with the GitHub account associated with this repository.
3. Include steps to reproduce and any relevant proof-of-concept code.

## Security Considerations

This project handles encrypted file transfers. Key security properties:

- **No plaintext storage**: All files are stored as opaque `crypto.SecureMessage` envelopes
- **Authenticity**: Ed25519 signatures verify sender identity on all write operations
- **Replay protection**: Nonce + timestamp + replay cache prevents message replay attacks
- **Rate limiting**: Per-sender, per-mailbox, per-IP rate limits prevent abuse
- **Bounded allocation**: All buffers are size-checked before allocation to prevent DoS

## Security Best Practices for Users

- Store `SERVER_SECRET` durably. Mailbox IDs are `HMAC-SHA256(SERVER_SECRET, pubkey)`, so **rotating it orphans every existing mailbox** — all in-flight transfers become unreachable. Keep it in a secret manager or environment-scoped secret storage, not in source control or image layers. It grants no access to message contents (the relay holds none) but does let an attacker predict mailbox IDs and impersonate the router's derivation.
- Rotate `read_secret` when you suspect compromise
- Monitor transfer expiry to avoid stale data in storage
- Validate chunk hashes before trusting downloaded content

## Disclosure Policy

We will acknowledge receipt within 48 hours and provide a timeline for fixes. Critical vulnerabilities will be patched within 7 days.
