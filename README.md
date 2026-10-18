# GeoTerra — Bangladesh Land Registration & Management Portal

GeoTerra is an independent web-based land management demonstration for Bangladesh. It combines user and administrator dashboards, land records, document submission and review, shared-ownership workflows, land calculations, map/weather information, and available police/registry contact directories. It is not a government service and does not establish legal title to land.

## Requirements

- Node.js 20+
- npm
- A modern browser

## Run locally

```bash
cp .env.example .env
```

Edit `.env` and replace every `REPLACE_WITH_...` value with unique secrets. Use three separate random secrets of at least 32 characters for `SESSION_SECRET`, `NID_HASH_SECRET`, and `NID_ENCRYPTION_SECRET`; set a unique administrator password of at least 12 characters. The server refuses to start if these required values are missing or still contain placeholders. Never commit `.env`. Then:

```bash
npm install
npm start
```

Open:
- User panel: http://localhost:3000/user.html
- Admin panel: http://localhost:3000/admin.html

The administrator account is provisioned from `ADMIN_USERNAME`, `ADMIN_PASSWORD`, and `ADMIN_NAME` at startup. The default username is `admin`, but no administrator password is bundled in this repository. The configured password hash is refreshed on server startup. If you change credentials, preserve the same `.env` secrets for existing data and do not expose them publicly.

## CAPTCHA

If `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are configured, the server validates Cloudflare Turnstile tokens. Obtain keys from Cloudflare Turnstile and configure the matching site key in `.env`. If not configured, the application uses its own server-session visual CAPTCHA for demonstration purposes. This is basic protection and is not equivalent to a commercial bot-mitigation service; configure Turnstile before internet-facing deployment.

## Data and storage

- SQLite database: `data/geoterra.sqlite`
- Session store: `data/sessions.sqlite`
- PDF files: `private_uploads/` (outside public static assets)
- Upload cap: `MAX_UPLOAD_MB` (default 10 MB)
- PDFs are checked by MIME type, size, and `%PDF-` signature. Malware scanning is not bundled; integrate a scanner before handling real legal documents.
- User land data is scoped by the authenticated user on the server. Admin endpoints check the administrator role on every request.

## Security notes before deployment

This is a hackathon starter, not a government service or a production legal-record system. Before public deployment:
1. Use HTTPS, a strong randomly generated `SESSION_SECRET`, and `NODE_ENV=production`.
2. Configure Cloudflare Turnstile.
3. Add MFA for administrators and email/SMS account recovery.
4. Add malware scanning, encrypted backups, retention policy, monitoring, and security review.
5. Restrict database/filesystem access and run the app behind a correctly configured reverse proxy.
6. Add a proper production session store and operational monitoring.
7. Consider a maintained CSRF library/middleware and review all dependencies before deployment.
8. Validate official helplines and office contacts against official sources before publishing them.

## Included features

- User registration and login with bcrypt password hashing and session cookies
- Server-validated CAPTCHA challenge, rate limiting, five-failure user lockout, idle session expiry
- Dedicated admin login and server-enforced lockout after three failed attempts for ten minutes
- User-owned land records (create, edit, delete when no documents are linked)
- PDF-only Dolil upload, size/MIME/signature checks, generated private filenames
- Shared admin review queue; under-review, approve, reject, correction-required decisions
- Per-document review history and in-app notifications
- User management, account suspension/reactivation, audit log
- District weather and satellite mapping widget in user panel (Open-Meteo + Esri/Leaflet)
- Explicit disclaimer that portal review is not government title verification

## API outline

- `GET /api/csrf`
- `GET /api/auth/captcha`
- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/admin/auth/login`
- `GET /api/me`, `POST /api/logout`
- `GET /api/dashboard`
- `POST /api/lands`, `PUT /api/lands/:id`, `DELETE /api/lands/:id`
- `POST /api/lands/:id/documents`, `GET /api/documents/:id/file`
- `GET /api/admin/overview`, `/api/admin/users`, `/api/admin/documents`, `/api/admin/audit`
- `POST /api/admin/documents/:id/review`, `POST /api/admin/users/:id/status`

## Tests

Run `npm test`. The included tests are lightweight unit tests for core validation rules; they are not a full security or endpoint integration suite. Run full endpoint/integration tests against a temporary database before deployment.

## NID and security notes

- Registration accepts exactly 10 numeric NID digits in this project version. The app stores a keyed hash rather than the raw NID and allows login with either username or NID. Keep `NID_HASH_SECRET` stable or existing NID-based logins will no longer match.
- Admin credentials are controlled by your local `.env` file. `ADMIN_USERNAME` defaults to `admin`; set a unique `ADMIN_PASSWORD` locally. No working admin password is included in the public source code. The configured password hash is refreshed on server startup.
- API rate limiting, short HTTP-only sessions, strict SameSite cookies, and login lockouts are enabled. These measures help with basic abuse but do not guarantee DDoS protection. Use a reverse proxy/WAF (such as Cloudflare), TLS, and host-level firewall/rate limits for a public deployment.
- NID is sensitive personal information. This demo does not perform official identity verification; do not collect real NIDs in a public deployment without appropriate legal/privacy safeguards.

## Expanded registration and document workflow (October 2026)

- Registration accepts exactly 10 numeric NID digits. The NID is keyed-hashed for uniqueness; raw registration NIDs are not stored. One NID hash can belong to only one account.
- Registration has a bilingual list of all 64 districts. The included police-station and post-office options are a starter set (Sadar, Model Thana, main/sadar post office) with a manual-entry option; they are **not** an exhaustive official police-station/post-office directory. Load a verified Bangladesh government or postal dataset before relying on this as a complete address directory.
- The login anti-bot check is a distorted visual CAPTCHA. It is not equivalent to a commercial bot mitigation service. Configure Cloudflare Turnstile for internet-facing deployment.
- Land registration distinguishes existing/own land from newly purchased land. Newly purchased land can be individual or shared. It supports separate reviewable uploads for Dolil, owner NID, owner photo, previous-owner NID/photo, payment receipt, and shareholder NID documents. Shared-purchase NID lists are encrypted at rest with AES-256-GCM; keep `NID_ENCRYPTION_SECRET` unchanged or those values cannot be decrypted.
- Administrators can review each file independently, request corrections, and view current sessions. Review decisions and notifications are stored in SQLite. Records persist until the database is deleted or corrupted; no application can promise they remain forever without off-site backups.
- The administrator panel sidebar fills the page height and the session list excludes raw session IDs/cookies.

## Data durability and privacy

Back up `data/geoterra.sqlite`, the session database in `data/`, and `private_uploads/` regularly to a protected location. Never commit `.env`, databases, NID data, or uploaded documents to source control. Use HTTPS, a reverse proxy/WAF, rate limits at the edge, malware scanning, encrypted backups, and a tested restore procedure before public deployment. CAPTCHA and application rate limits alone do not stop distributed denial-of-service attacks.




## GitHub publication checklist

Before pushing this repository, confirm that `.env`, `data/`, `private_uploads/`, database files, logs, and real user documents are not staged or committed. The included `.gitignore` excludes these paths, but always inspect `git status` and staged files before the first push. If a real secret was committed in an earlier Git commit, changing the current file is not enough; rotate that secret and clean the Git history before making the repository public.

This repository intentionally contains `.env.example` with placeholders only. Copy it to `.env` for local use and replace all placeholder values before starting the server. Never use production land documents or real national ID information in a public demo.
