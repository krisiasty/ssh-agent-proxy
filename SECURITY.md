# Security Policy

`ssh-agent-proxy` sits on an authentication boundary. Reports that could expose
an unconfigured key, permit unauthorized signing, bypass socket ownership, or
otherwise weaken that boundary are treated as security issues.

## Supported versions

Security fixes are made for the latest released version. Before reporting a problem,
please reproduce it with the newest release when practical.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Do not open a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/krisiasty/ssh-agent-proxy/security/advisories/new)
to send the report to the maintainer.

Include the affected version, operating system and architecture, upstream agent,
impact, and minimal reproduction steps. Logs are useful, but remove usernames,
filesystem paths, key comments, fingerprints, and any other identifying
information first. Never include a private key, passphrase, signing payload,
authentication token, or repository secret.

You should receive an acknowledgement after the report is reviewed. Disclosure timing
will be coordinated with the reporter when a fix is required.
