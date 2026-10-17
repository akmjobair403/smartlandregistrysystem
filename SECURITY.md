# Security Policy

## Scope

GeoTerra is a demonstration land-management application. It is not certified for production handling of legal land records or national identity data.

## Reporting a vulnerability

Please do not publish real passwords, national ID numbers, land documents, session cookies, or other personal data in a public issue. For a private report, use GitHub's private vulnerability reporting feature if it is enabled for this repository. Otherwise, contact the repository maintainer privately before disclosing details.

## Before deployment

- Set unique values for all secrets in `.env`; never commit `.env`.
- Use HTTPS and secure production cookie settings.
- Configure a production-grade anti-bot service and review authentication/authorization controls.
- Add malware scanning for uploads, encrypted backups, monitoring, retention controls, and a tested recovery plan.
- Do not process real NID or land-registration documents until legal, privacy, and security requirements have been reviewed.
