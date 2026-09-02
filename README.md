# SecureChat

A real-time web chat application built to demonstrate applied cryptography and
secure-application design: multi-factor login, encrypted message storage, HMAC
integrity verification, and role-based access control.

Built as the Lab Evaluation 1 project for **23CSE313 – Foundations of Cyber Security (FoCS)**.

---

## What it does

Users sign up, log in with a password plus a one-time code, and exchange messages
in group rooms or one-to-one DMs. Messages travel over WebSockets and are stored
encrypted — the database never holds plaintext. Every message also carries an
HMAC tag, so a row tampered with directly in the database is detected and shown
as `[Integrity check failed]` instead of being silently trusted.

## Security design

| Area | Mechanism |
| --- | --- |
| Password storage | PBKDF2-HMAC-SHA256, 260,000 iterations, 16-byte per-user random salt |
| Password comparison | `hmac.compare_digest` (constant-time) |
| Second factor | 6-digit OTP, 60-second TTL, 20-second resend rate limit |
| Message confidentiality | Fernet (AES-128-CBC + HMAC), key held outside the codebase |
| Message integrity | HMAC-SHA256 tag per message, verified on read |
| Authorization | ACL mapping roles (`user` / `admin` / `owner`) to actions |
| Injection defence | Parameterized SQL throughout; username and password format validation |
| SQLite hardening | `foreign_keys=ON`, `journal_mode=WAL`, `trusted_schema=OFF` |

A fuller write-up of each control lives in [docs/security-features.md](docs/security-features.md).

## Tech stack

Python · Flask · Flask-SocketIO (eventlet) · SQLite · `cryptography` (Fernet) · Bootstrap

## Running it locally

```bash
pip install -r requirements.txt
```

```bash
python db.py && python createadmindb.py
```

```bash
python app.py
```

Then open <http://localhost:5000>.

`db.py` creates the message table and `createadmindb.py` seeds a default `admin`
and `owner` account. The Fernet and HMAC keys are generated automatically on
first run and written to `fernet.key` / `integrity.key`, which are gitignored.

The OTP is printed to the server console rather than sent by SMS or email — this
is a deliberate demo shortcut, not a delivery mechanism.

## Project layout

```
app.py                  Flask routes, Socket.IO handlers, crypto and DB helpers
db.py                   Creates the messages table
createadmindb.py        Seeds default admin / owner accounts
createmessageroomdb.py  Legacy migration: adds the signature column to older DBs
upgrade_admin.py        Promotes an existing account to admin
templates/              Jinja2 templates (login, OTP, chat, account, admin views)
docs/                   Security write-up, rubric mapping, problem statement
```

## Known limitations

This is a coursework project, and a few things are deliberately simplified:

- Encryption is server-side, not end-to-end — the server can read every message.
- OTP delivery is console-only.
- Keys are loaded from local files rather than a secrets manager, and
  `FLASK_SECRET_KEY` falls back to a hardcoded default if the environment
  variable is unset.
- Password verification still accepts the legacy SHA-256 format for accounts
  created before the PBKDF2 migration.
- There is no automated test suite.
