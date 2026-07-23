# Security Policy

## Supported version

Security fixes target the current `main` branch. AutoLean is pre-release software; no historical
release branch currently receives security updates.

## Private reporting

Report a vulnerability through
[GitHub private vulnerability reporting](https://github.com/Wenbobobo/AutoLean/security/advisories/new).
Do not open a public issue for credential exposure, sandbox escape, verifier bypass, statement
substitution, signature/replay weakness, restricted-data disclosure, or provider-policy bypass.

Do not paste a live credential, private prompt, model output, recovered archive listing, or source
document into the report. Revoke an exposed credential first and identify it only by provider,
scope, and rotation timestamp. Use minimal synthetic reproduction data whenever possible.

## Evidence boundary

A repository scan cannot contain an incident outside GitHub. Dataset access control, credential
rotation, endpoint revocation, and deletion of external artifacts remain operator actions. A
proof-search failure or incorrect mathematical statement is not itself a software vulnerability,
but a path that silently weakens a frozen statement or bypasses independent verification is.
