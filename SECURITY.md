# Security Features & Hardening

## Account Management
- ✅ **Change Username**: Users can update their username with password verification
- ✅ **Delete Account**: Secure account deletion with password + username confirmation
  - All associated messages deleted
  - All DM conversations deleted
  - Account data completely removed

## Database Security
- ✅ **Parameterized Queries**: All SQL uses `?` placeholders to prevent SQL injection
- ✅ **Foreign Keys Enabled**: `PRAGMA foreign_keys = ON`
- ✅ **Write-Ahead Logging (WAL)**: `PRAGMA journal_mode = WAL` for transaction consistency
- ✅ **Trusted Schema Disabled**: `PRAGMA trusted_schema = OFF`
- ✅ **Input Validation**:
  - Usernames: 3-50 alphanumeric characters
  - Passwords: 6-200 characters minimum
  - Prevents SQL injection and malformed data

## Authentication & Encryption
- ✅ **Password Hashing**: PBKDF2-HMAC-SHA256 (260,000 iterations)
  - Backward compatible with legacy SHA256 hashes
  - Random 16-byte salt per user
- ✅ **Message Encryption**: Fernet (AES-128 in CBC mode)
  - Encrypted messages stored in database
  - HMAC-SHA256 integrity verification
- ✅ **OTP MFA**: 6-digit one-time password (60-second TTL)
  - Rate-limited resend (20-second minimum)
  - Console-printed for demo (enterprise: use SMS/email)

## Session Security
- ✅ **Session Verification**: All routes verify `session["mfa"]` flag
- ✅ **Session Isolation**: Each user isolated to their own account
- ✅ **Admin Access Control**: Delete operations restricted to role="admin"

## Sensitive Operations
- ✅ **Password Verification Required For**:
  - Changing username
  - Deleting account
- ✅ **Confirmation Mechanisms**:
  - Username entry confirmation before account deletion
  - JavaScript prompt warning before deletion
- ✅ **Transaction Safety**: Atomic operations for account deletion

## Data Integrity
- ✅ **Message Signatures**: HMAC-SHA256 per message
- ✅ **Corruption Handling**: Displays "[Integrity check failed]" for tampered messages
- ✅ **Encryption Key Management**:
  - Persistent keys in files (fernet.key, integrity.key)
  - Prevents key rotation issues
  - 32-byte integrity key validation

## Best Practices Implemented
- Automatic SQLite error handling
- Exception catching for all database operations
- Secure random token generation (secrets module)
- HTTPS-ready (production: use SSL/TLS)
- Admin-only message deletion
- Role-based access control (ACL)

## Future Recommendations
- Enable HTTPS/TLS in production
- Add rate limiting (login attempts, API calls)
- Implement password reset via secure email
- Add two-factor authentication (TOTP with QR codes)
- Database backups with encryption
- Audit logging for sensitive operations
- Implement CSRF protection
- Add Content Security Policy (CSP) headers
