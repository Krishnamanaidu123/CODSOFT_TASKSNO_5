# CODSOFT_TASKSNO_5

# Secure File Sharing System

A file-sharing API with authenticated uploads/downloads, AES-256-GCM
encryption at rest, role-based access control, and temporary expiring
download links.

Built with Node.js + Express + SQLite (via `better-sqlite3`).

## Features

- **Authentication** — JWT-based, passwords hashed with bcrypt (cost 12).
- **Encryption at rest** — every file is encrypted with AES-256-GCM using a
  unique random IV per file before it ever touches disk. The server never
  stores plaintext.
- **Role-based access control** — three roles (`user` < `manager` < `admin`)
  plus per-file explicit grants and a per-file visibility floor, so access
  can be controlled both by hierarchy and by direct sharing.
- **Temporary share links** — bearer tokens with configurable expiry and an
  optional max-download cap, usable without authentication (e.g. to send to
  someone outside the system).
- **Tamper detection** — GCM's authentication tag is verified *before* any
  response bytes are sent, so a corrupted or tampered ciphertext fails
  closed instead of leaking partial plaintext.
- **Audit log** — uploads, downloads, denials, permission changes, and
  share-link activity are all recorded.

## Quick start

```bash
npm install
cp .env.example .env
```

Generate two real secrets and put them in `.env`:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # -> FILE_ENCRYPTION_KEY
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"   # -> JWT_SECRET
```

`FILE_ENCRYPTION_KEY` **must** be a 64-character hex string (32 bytes) — the
server refuses to start otherwise.

```bash
npm start
```

The server listens on `PORT` (default `3000`) and initializes its SQLite
schema automatically on first run.

## Data model / RBAC design

| Role      | Level | Can do |
|-----------|-------|--------|
| `user`    | 1     | Own files; files explicitly shared with them; files with `min_role: user` |
| `manager` | 2     | Everything a `user` can, plus files with `min_role: manager` |
| `admin`   | 3     | Everything, on every file, plus user/role management |

Every file also has a `min_role` visibility floor set at upload time
(`user`, `manager`, `admin`, or `owner_only` — the default). This lets an
uploader decide "anyone at manager level or above can see this" without
manually sharing with each person, while `owner_only` means nobody but the
owner (and admins) can see it until it's explicitly shared.

Independent of that hierarchy, an owner (or admin) can grant a specific user
`read` or `write` access via `POST /files/:id/permissions` — this works even
if the recipient's role is below the file's `min_role`.

Write/delete actions always require being the owner, an admin, or holding an
explicit `write` grant — role level alone never grants write access.

Self-registration always creates `user`-role accounts; promotion to
`manager`/`admin` is an admin-only action (`PATCH /admin/users/:id/role`),
so a client can never elevate its own privileges by tampering with a
request body.

## Encryption design

- **Algorithm**: AES-256-GCM (authenticated encryption).
- **Key**: a single 32-byte master key from `FILE_ENCRYPTION_KEY` (env var,
  never stored in the database). In a real deployment this should come from
  a KMS/secrets manager rather than a flat file.
- **IV**: 96-bit, cryptographically random, generated fresh per file and
  stored alongside the file's metadata (not secret — IVs are safe to store
  in the clear, only the key must remain secret).
- **Auth tag**: GCM's 128-bit tag is stored per file and checked on every
  read.
- **Verify-before-serve**: decryption reads the full ciphertext, decrypts,
  and calls the auth-tag check *before* the HTTP response is written. If
  the tag doesn't match (corruption or tampering), the request fails with
  `500` and nothing is ever sent to the client. This trades memory (whole
  file buffered) for correctness; a production system handling very large
  files would instead use a chunked envelope format (each chunk encrypted
  and authenticated independently) to allow streaming without that
  trade-off.
- **Share tokens**: the raw bearer token for a share link is returned to
  the creator exactly once and only its SHA-256 hash is persisted — so a
  database leak alone doesn't hand out working download links.

## API reference

All authenticated routes take `Authorization: Bearer <token>`.

### Auth
| Method | Path | Description |
|---|---|---|
| POST | `/auth/register` | `{ username, email, password }` → creates a `user`-role account |
| POST | `/auth/login` | `{ username, password }` → JWT |
| GET | `/auth/me` | Current user info |

### Files
| Method | Path | Description |
|---|---|---|
| POST | `/files` | Multipart upload, field `file`; optional `min_role` field |
| GET | `/files` | List files visible to the caller |
| GET | `/files/:id/download` | Download + decrypt (RBAC enforced) |
| DELETE | `/files/:id` | Delete (owner/admin/write-grant only) |
| POST | `/files/:id/permissions` | `{ user_id, permission: "read"\|"write" }` — owner/admin only |
| DELETE | `/files/:id/permissions/:userId` | Revoke a grant |

### Share links (bonus feature)
| Method | Path | Description |
|---|---|---|
| POST | `/files/:id/share` | `{ expires_in_minutes?, max_downloads? }` → one-time-visible token + URL |
| GET | `/files/:id/share` | List active links for a file (owner/admin) |
| DELETE | `/files/:id/share/:linkId` | Revoke a link early |
| GET | `/share/:token` | **Public**, unauthenticated — redeems the link |

### Admin
| Method | Path | Description |
|---|---|---|
| GET | `/admin/users` | List all users |
| PATCH | `/admin/users/:id/role` | `{ role }` — promote/demote |
| PATCH | `/admin/users/:id/status` | `{ is_active }` — disable an account |

## Security notes / hardening already included

- `helmet` for standard security headers.
- Rate limiting on `/auth/*` (brute-force), `/share/*` (token-guessing), and
  globally.
- Login responses are constant-shape whether the username exists or not, to
  reduce username enumeration.
- Uploaded files land briefly in a non-web-exposed temp directory and are
  deleted immediately after encryption (success or failure) — plaintext
  never lingers on disk.
- Share-link redemption increments the download counter atomically in the
  same SQL statement as the eligibility check, closing the race where two
  simultaneous requests could both succeed against a `max_downloads: 1` link.

## What a production hardening pass would add next

- Move the master encryption key to a real KMS/HSM with per-file data keys
  (envelope encryption) instead of one static key from an env var.
- Chunked/streaming authenticated encryption for large files.
- Refresh tokens / token revocation list (current JWTs are valid until
  natural expiry).
- Structured logging + alerting on the audit log instead of a plain table.
- Virus/malware scanning on upload.
