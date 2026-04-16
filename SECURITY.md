# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.1.x   | :white_check_mark: |
| < 1.1   | :x:                |

## Reporting a Vulnerability

Security Shield is itself a security product, so responsible disclosure is critical.

If you discover a security vulnerability:

1. **Do NOT** open a public issue
2. Email the maintainer or open a private security advisory via [GitHub Security Advisories](https://github.com/hrygo/security-shield/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)

You will receive a response within **48 hours**. If the issue is confirmed, we will:

- Work on a fix within **7 days**
- Release a patched version promptly
- Credit you in the release notes (unless you prefer to remain anonymous)

## Security Best Practices for Users

- Keep the plugin updated to the latest version
- Configure `l0Users` with only trusted admin accounts
- Monitor audit logs regularly for attack patterns
- Set appropriate risk thresholds for your environment
- Do not disable Layer 1 (input guard) — it has zero overhead
