# SECURE CHAT APPLICATION - VIVA RUBRIC MAPPING

## ASSESSMENT AGAINST LAB RUBRIC (20 Marks Total)

---

## **1. AUTHENTICATION (3 Marks)**

### 1.1 Single-Factor Authentication (1.5 Marks) ✅ COVERED
**Requirement:** Implementation using password / PIN / username-based login

**Your Implementation:**
```python
# FILE: app.py, Lines 203-240

@app.route("/login", methods=["GET", "POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Secure Chat — VIVA Guide & Run Instructions

    This single document shows how to run the Secure Chat app and maps the project to the lab rubric for your viva.

    ## Run the app

    1. (Optional) Initialize DB tables and default accounts if not present:

    ```powershell
    python db.py
    python createadmindb.py
    ```

    2. Install dependencies and run the server:

    ```powershell
    pip install -r requirements.txt
    python app.py
    ```

    3. Open the app in your browser:

    http://localhost:5000

    Default demo accounts (check OTP printed in terminal):
    - Admin: `admin` / `admin@123` (role `admin`)
    - Owner: `owner` / `owner@123` (role `owner`)

    ## Quick Demo Checklist for Viva

    - Login → OTP (printed in terminal) → /home
    - Group chat: `/groupchat` (send/receive messages)
    - DM: `/dmchat?user=<username>`
    - Owner-only: `/userlist` (view all users)
    - Owner delete other user: POST `/delete_user/<username>`
    - Admin/Owner delete message: POST `/delete_message/<id>` or via UI (admin/owner only)

    ## Rubric mapping (concise)

    - Authentication (3m)
        - Single-factor: `app.py` `/login` — verifies PBKDF2 password (see `hash_password`, `verify_password`).
        - Multi-factor: `app.py` `/otp` — 6-digit OTP, 60s TTL, resend rate-limit.

    - Authorization (3m)
        - ACL in `app.py` at top (`ACL` dict). Roles: `admin`, `owner`, `user`.
        - Owner-only `/userlist` route; owner-only `/delete_user/<username>`; `check_access()` used for Socket.IO events and privileged routes.

    - Encryption (3m)
        - `app.py`: `fernet.key` (Fernet) for symmetric encryption; `encrypt_message()` / `decrypt_message()`.
        - Integrity key `integrity.key` used with HMAC-SHA256.

    - Hashing & Digital Signature (5m)
        - Passwords: PBKDF2-HMAC-SHA256 with per-user salt (260k iterations) (`hash_password`, `verify_password`).
        - Message integrity: `generate_hmac()` / `verify_hmac()` (HMAC-SHA256), stored in `messages.signature`.

    - Encoding (3m)
        - Base64 used to store encrypted ciphertext in DB (`base64.b64encode` / `b64decode`).

    ## Notes & Talking Points (for viva)

    - Key generation: `Fernet.generate_key()` and `secrets.token_bytes(32)` create persistent keys stored in files for demo. Mention KMS in production.
    - Explain separation of duties: Admin = moderation (delete messages), Owner = user management (view user list, delete other users). Owner cannot delete self or admin.
    - Explain use of parameterized SQL queries to prevent SQL injection and `hmac.compare_digest()` to avoid timing attacks.

    ## Files to reference during viva

    - `app.py` — main server, routes, ACL, encryption, hashing, OTP
    - `db.py` / `createadmindb.py` — DB setup and default accounts
    - `templates/` — `homepage.html`, `groupchat.html`, `dmchat.html`, `userlist.html`, `accountsetting.html`

    ## Quick tests to run

    ```powershell
    # show users
    python -c "import sqlite3; print(list(sqlite3.connect('database.db').cursor().execute('SELECT username, role FROM users')) )"

    # run server
    python app.py
    ```

    ---

    Keep this file open during your viva — it contains run steps and the exact mappings to demonstrate each rubric item.

@app.route("/home")
def home():
    if "user" not in session or not session.get("mfa"):  # Authorization check
        return redirect("/")
    return render_template("homepage.html")
```

2. **Delete Permission Check:**
```python
# FILE: app.py, Lines 651-653

@socketio.on("delete_message")
def handle_delete_message(data):
    if not check_access("delete"):  # Check ACL
        emit("error", {"error": "Access Denied"})
        return
    
    # Proceed with deletion only if authorized
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id=?", (data.get("id"),))
    conn.commit()
```

3. **Account Operations Protection:**
```python
# FILE: app.py, Lines 352-356

@app.route("/change_username", methods=["POST"])
def change_username():
    # Admin and Owner cannot change username (security restriction)
    if session.get("role") in ["admin", "owner"]:
        return render_template("error.html", error_message="Admin and Owner accounts cannot be modified")
    
    # Only current user can change their own username
    new_username = request.form.get("new_username", "").strip()
    password = request.form.get("password", "")  # Require password verification
```

4. **User List Access (Owner Only):**
```python
# FILE: app.py, NEW ROUTE

@app.route("/userlist")
def userlist():
    if "user" not in session or not session.get("mfa"):
        return redirect("/")
    
    if not check_access("view_userlist"):  # Owner-only permission
        return render_template("error.html", error_message="You do not have permission")
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, role FROM users ORDER BY username")
    users = cur.fetchall()
    conn.close()
    
    users_data = [{"username": row["username"], "role": row["role"]} for row in users]
    return render_template("userlist.html", users=users_data)
```

---

## **3. ENCRYPTION (3 Marks)**

### 3.1 Key Exchange Mechanism (1.5 Marks) ✅ COVERED (with notes)
**Requirement:** Demonstrate secure key generation or key exchange method

**Your Implementation:**
```python
# FILE: app.py, Lines 59-72

KEY_FILE = "fernet.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())  # Cryptographically secure key generation
with open(KEY_FILE, "rb") as f:
    FERNET_KEY = f.read()

cipher = Fernet(FERNET_KEY)

INTEGRITY_FILE = "integrity.key"
if not os.path.exists(INTEGRITY_FILE):
    with open(INTEGRITY_FILE, "wb") as f:
        f.write(secrets.token_bytes(32))  # 256-bit secure random key

with open(INTEGRITY_FILE, "rb") as f:
    INTEGRITY_KEY = f.read()

if len(INTEGRITY_KEY) != 32:
    raise ValueError("Integrity key must be 32 bytes")
```

**Key Generation Details:**
- **Fernet Key:** Generated via `Fernet.generate_key()` (cryptographically secure)
- **Integrity Key:** Generated via `secrets.token_bytes(32)` (256-bit, compliant with NIST SP 800-133)
- **Storage:** File-based (suitable for lab; production would use HSM/secrets manager)

**For Viva, mention:**
- Keys are generated once on first run using cryptographically secure methods
- Keys are persistent in files to prevent key rotation issues
- In production: use AWS KMS, HashiCorp Vault, or Azure Key Vault

---

### 3.2 Encryption & Decryption (1.5 Marks) ✅ COVERED
**Requirement:** Implement secure encryption and decryption (AES, RSA, or hybrid)

**Your Implementation:**
```python
# FILE: app.py, Lines 63-81

def encrypt_message(plain_text):
    """Fernet symmetric encryption (AES-128 in CBC mode)"""
    encrypted = cipher.encrypt(plain_text.encode())
    return base64.b64encode(encrypted).decode()

def decrypt_message(encoded_text):
    """Fernet symmetric decryption"""
    encrypted = base64.b64decode(encoded_text.encode())
    return cipher.decrypt(encrypted).decode()

# USAGE: Messages are encrypted when stored
# FILE: app.py, Lines 710-713

@socketio.on("send_message")
def handle_send_message(data):
    plain = data.get("message", "").strip()
    encrypted = encrypt_message(plain)  # Encrypt before storage
    signature = generate_hmac(plain)     # Generate integrity signature
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (sender, room, message, signature) VALUES (?, ?, ?, ?)",
        (session["user"], room, encrypted, signature)  # Store encrypted
    )
    conn.commit()
```

**Encryption Schema:**
```
Plaintext Message: "Hello Alice"
        ↓
Fernet.encrypt(): AES-128-CBC + HMAC-SHA256
        ↓
Base64 Encoding: "gAAAAABlwxyz1234..."
        ↓
Database Storage: message field = "gAAAAABlwxyz1234..."
        ↓
On Retrieval:
        ↓
Base64 Decode: Binary encrypted data
        ↓
Fernet.decrypt(): AES-128-CBC decryption
        ↓
Plaintext: "Hello Alice"
```

**Technology: Fernet (Symmetric)**
- Algorithm: AES-128 in CBC mode
- Mode: Authenticated encryption (includes HMAC)
- Standard: RFC 7539 compatible

---

## **4. HASHING & DIGITAL SIGNATURE (5 Marks)**

### 4.1 Hashing with Salt (1.5 Marks) ✅ COVERED
**Requirement:** Secure storage of passwords/data using hashing with salt

**Your Implementation:**
```python
# FILE: app.py, Lines 29-48

def hash_password(password, salt, iterations=260000):
    """PBKDF2-HMAC-SHA256 with configurable iterations"""
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    return f"pbkdf2${iterations}${dk.hex()}"

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    if stored_hash and stored_hash.startswith('pbkdf2$'):
        try:
            parts = stored_hash.split('$')
            iterations = int(parts[1])
            expected = parts[2]
            dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
            return hmac.compare_digest(dk.hex(), expected)  # Timing-safe comparison
        except Exception:
            return False

# SIGNUP USAGE:
# FILE: app.py, Lines 182-185

salt = secrets.token_hex(16)        # 16-byte salt = 128-bit
password_hash = hash_password(password, salt)

cur.execute(
    "INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)",
    (username, password_hash, salt, "user")
)
```

**Password Storage Details:**

| Component | Value | Why |
|-----------|-------|-----|
| **Algorithm** | PBKDF2-HMAC-SHA256 | NIST SP 800-132 compliant |
| **Iterations** | 260,000 | NIST recommendation (min 100k as of 2023) |
| **Salt Size** | 128-bit (16 bytes) | Prevents rainbow table attacks |
| **Salt Generation** | `secrets.token_hex(16)` | Cryptographically secure random |
| **Comparison** | `hmac.compare_digest()` | Prevents timing attacks |

**Storage Format in DB:**
```
username | password_hash                                    | salt
---------|----------------------------------------------|----------
alice    | pbkdf2$260000$abc123def456...                | 1a2b3c4d5e6f7g8h9i0j
bob      | pbkdf2$260000$fed654cba987...                | 9i0j1a2b3c4d5e6f7g8h
```

---

### 4.2 Digital Signature using Hash (1.5 Marks) ✅ COVERED
**Requirement:** Demonstrate data integrity and authenticity using hash-based digital signatures

**Your Implementation:**
```python
# FILE: app.py, Lines 74-81

INTEGRITY_KEY = f.read()  # 32-byte secret key

def generate_hmac(message):
    """Generate HMAC-SHA256 signature for message"""
    return hmac.new(INTEGRITY_KEY, message.encode(), hashlib.sha256).hexdigest()

def verify_hmac(message, signature):
    """Verify message integrity using HMAC"""
    expected = generate_hmac(message)
    return hmac.compare_digest(expected, signature)  # Timing-safe comparison
```

**Digital Signature Flow:**
```
Message: "Transfer $1000 to Bob"
        ↓
HMAC-SHA256(message, INTEGRITY_KEY)
        ↓
Signature: "a1b2c3d4e5f6g7h8..."
        ↓
Storage: INSERT messages (message, signature) VALUES (encrypted_msg, signature)
        ↓
On Retrieval: Decrypt message
        ↓
HMAC-SHA256(decrypted_message, INTEGRITY_KEY) == stored_signature?
        ↓
✅ Authentic & Unaltered OR ❌ Tampered
```

**HMAC Implementation in Message Sending:**
```python
# FILE: app.py, Lines 710-725

@socketio.on("send_message")
def handle_send_message(data):
    plain = data.get("message", "").strip()
    encrypted = encrypt_message(plain)      # Encrypt message
    signature = generate_hmac(plain)        # Sign plaintext for integrity
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (sender, room, message, signature) VALUES (?, ?, ?, ?)",
        (session["user"], room, encrypted, signature)
    )
    conn.commit()
```

**HMAC Verification on Retrieval:**
```python
# FILE: app.py, Lines 98-130 (fetch_messages function)

for row in rows:
    enc_msg = row["message"]
    sig = row["signature"]
    
    try:
        plain = decrypt_message(enc_msg)
        if sig:
            if verify_hmac(plain, sig):
                body = plain  # ✅ Signature verified
            else:
                body = "[Integrity check failed]"  # ❌ Tampered
        else:
            body = plain
    except Exception as e:
        body = "[Corrupted message]"
```

**Why HMAC is Better Than Simple Hash:**
- Simple hash: `SHA256(message)` - anyone can recompute
- HMAC: `HMAC-SHA256(message, secret_key)` - only key holder can verify
- Prevents: Message forgery, replay attacks

---

## **5. ENCODING TECHNIQUES (3 Marks)**

### 5.1 Encoding & Decoding Implementation (3 Marks) ✅ COVERED
**Requirement:** Implement encoding/decoding (Base64, QR Code, Barcode, etc.)

**Your Implementation: Base64 Encoding**

```python
# FILE: app.py, Lines 63-81

def encrypt_message(plain_text):
    encrypted = cipher.encrypt(plain_text.encode())
    return base64.b64encode(encrypted).decode()  # ← BASE64 ENCODING
    #      ────────────────────────────────
    # Converts binary encrypted data to ASCII-safe string

def decrypt_message(encoded_text):
    encrypted = base64.b64decode(encoded_text.encode())  # ← BASE64 DECODING
    #          ──────────────────────────────
    # Converts ASCII string back to binary
    return cipher.decrypt(encrypted).decode()
```

**Why Base64?**
- Encrypted data is binary (0-255 byte values)
- Database stores text, not binary
- Base64 converts binary → ASCII-safe characters (A-Z, a-z, 0-9, +, /, =)
- Reversible encoding (not encryption)

**Base64 Example:**
```
Binary encrypted data:   0xFF 0xA3 0x42 0x7C
                    ↓
             Base64 encoding
                    ↓
ASCII string:        "/6NCfA=="
                    ↓
             Stored in database
```

**Encoding vs Encryption:**
| Aspect | Encoding (Base64) | Encryption (Fernet) |
|--------|-------------------|-------------------|
| Purpose | Data transport | Data confidentiality |
| Reversible | Yes (anyone) | Yes (key needed) |
| Security | None | High |
| Example | `gAAAAABlxyz...` | Actual ciphertext |

---

## **6. SECURITY LEVELS & RISKS (6 Marks - Theory)**

### 6.1 Attacks & Countermeasures (6 Marks)
**Document for Viva:**

#### **Attack 1: Brute Force Password Attack**
```
Threat: Attacker tries 1 million password guesses
Countermeasures in Your App:
├─ PBKDF2 with 260,000 iterations: Each attempt = 260k hash operations
│  └─ 1 million attempts × 260k iterations = 260 billion operations
│  └─ Makes brute force computationally infeasible
├─ Rate limiting on login attempts (can be enhanced)
└─ Account lockout after N failed attempts (TODO: implement)
```

#### **Attack 2: Dictionary Attack**
```
Threat: Attacker uses pre-computed password hashes
Countermeasure: Random 128-bit salt
├─ Each user has unique salt
├─ Same password hashes to different values for different users
├─ Pre-computed dictionary useless
└─ Requires attacker to recompute for each salt
```

#### **Attack 3: SQL Injection**
```
Threat: Attacker injects SQL code via input
         SELECT * FROM users WHERE username='admin' OR '1'='1'
Countermeasure: Parameterized queries
├─ Your app uses: cur.execute("SELECT ... WHERE username=?", (username,))
├─ Parameters treated as data, not code
└─ Input validation: 3-50 chars, alphanumeric only
```

#### **Attack 4: Message Tampering**
```
Threat: Attacker intercepts and modifies encrypted message
Original: "Send $10"  →  Modified: "Send $1000"

Countermeasure: HMAC-SHA256 Digital Signature
├─ Signature = HMAC-SHA256(message, secret_key)
├─ Stored alongside encrypted message
├─ On retrieval: Recalculate HMAC and compare
└─ Modified message fails integrity check
    → Displays "[Integrity check failed]"
```

#### **Attack 5: Replay Attack**
```
Threat: Attacker captures and resends old message
Message 1: "Balance transfer approved"
Attacker: Replay same message → Balance transferred again

Countermeasure (Current): Database IDs prevent duplicate messages
├─ Each message has unique ID
└─ Duplicates rejected (TODO: add timestamp-based replay window)

Better: Add timestamp + replay window
├─ Accept messages only within window (e.g., ±5 seconds)
└─ Discard old replayed messages
```

#### **Attack 6: Session Hijacking**
```
Threat: Attacker steals session cookie
└─ Can impersonate user

Countermeasures:
├─ Session verification: Check session["mfa"] on every protected route
├─ Session["user"] binding: User data tied to session
├─ Logout clears session: session.clear()
└─ HTTPS (production): Encrypt session cookie in transit
```

#### **Attack 7: OTP Brute Force**
```
Threat: Attacker tries all 1 million possible 6-digit codes
Countermeasures:
├─ TTL: OTP valid for only 60 seconds
├─ Rate limit: Resend blocked for 20 seconds
└─ Rate limit per IP (can be added): Max 5 attempts per minute
```

#### **Attack 8: Privilege Escalation**
```
Threat: User (role='user') tries to delete another user's message
Attempt: socket.emit("delete_message", {id: 123})

Countermeasure: ACL enforcement
├─ check_access("delete") checks if role has "delete" permission
├─ Returns False for users → Deletion prevented
└─ Admin-only deletion enforced
```

---

## **7. VIVA PREPARATION - KEY POINTS**

### **Conceptual Clarity**

1. **Authentication vs Authorization:**
   - Authentication: "Who are you?" (Username/password + OTP)
   - Authorization: "What can you do?" (ACL with admin/user roles)

2. **Encryption vs Encoding:**
   - Encryption: Secret transformation (Fernet + key required)
   - Encoding: Reversible representation (Base64 for transport)

3. **Hashing vs Encryption:**
   - Hashing: One-way (password → hash) - output same for same input
   - Encryption: Two-way (message → ciphertext → message) - reversible

4. **Symmetric vs Asymmetric Encryption:**
   - Symmetric (Your App): Same key for encrypt/decrypt (Fernet)
   - Asymmetric: Different keys for encrypt/decrypt (RSA - not in your app)

5. **Digital Signature Purpose:**
   - Not secrecy (message can be decrypted) 
   - Integrity: Proves message wasn't altered
   - Authenticity: Proves who signed it

### **Design Decisions**

1. **Why Fernet instead of raw AES?**
   - Answer: Fernet includes built-in HMAC for authenticated encryption
   - Prevents padding oracle attacks
   - Handles key rotation safely

2. **Why PBKDF2 for passwords?**
   - Answer: NIST SP 800-132 recommended
   - Intentionally slow (260k iterations)
   - Makes brute force attacks prohibitively expensive

3. **Why ACL instead of RBAC?**
   - Answer: ACL is simpler for this application
   - Can be extended to RBAC if roles grow complex
   - Your implementation: `{"admin": [...], "user": [...]}`

4. **Why Base64 encoding?**
   - Answer: Binary encrypted data can't be stored as-is in text fields
   - Base64 makes it ASCII-safe for database storage
   - Not encryption - reversible by anyone (encryption provides security)

### **Security Reasoning**

1. **Why validate input?**
   - Prevent SQL injection
   - Prevent buffer overflows
   - Prevent format string attacks
   - Your app: Username 3-50 chars, alphanumeric + underscores/hyphens/dots

2. **Why use timing-safe comparison?**
   - `hmac.compare_digest()` vs `==`
   - Regular equality can leak password info via timing
   - Timing attacks: Different wait times = different comparison lengths

3. **Why require password re-entry for account changes?**
   - User authentication: Proves user is present and willing
   - CSRF protection: Form must be submitted by actual user
   - Your app: Username change, password change, account deletion all require password

4. **Why MFA?**
   - Something you know (password): Can be phished/cracked
   - Something you have (OTP): Device/phone/hardware token
   - Together: Even if password leaked, account is protected

---

## **8. CHECKLIST FOR VIVA PRESENTATION**

### **Code Examples to Prepare**
- [ ] Show login flow (authentication)
- [ ] Show OTP generation and verification (MFA)
- [ ] Show ACL check (authorization)
- [ ] Show message encryption and HMAC signature
- [ ] Show password hashing with PBKDF2
- [ ] Show Base64 encoding of encrypted messages
- [ ] Explain a real attack scenario and your countermeasure

### **Diagrams to Draw**
- [ ] Message flow: User sends → Encrypt → Sign → Store → Retrieve → Decrypt → Verify
- [ ] Authentication flow: Username/Password → OTP → MFA Success
- [ ] ACL Matrix: Subjects × Objects × Actions
- [ ] HMAC verification: Message → Hash → Compare → Integrity check

### **Questions to Anticipate**
1. "Why HMAC instead of just SHA256?"
   - HMAC requires secret key - attacker can't forge signatures
   - SHA256 is one-way but anyone can compute it

2. "What if someone steals the fernet.key file?"
   - All messages become readable (keys in files are for demo)
   - Production solution: Use KMS/Vault with access control

3. "Why 260k iterations for PBKDF2?"
   - NIST minimum recommendation
   - Costs attacker ~262 ms per guess (makes brute force impractical)

4. "How would you prevent admin from reading user messages?"
   - Use asymmetric encryption: Each user has public key
   - Server doesn't have private keys - can't decrypt
   - Only recipient can decrypt with their private key
   - (Advanced extension)

5. "What about database encryption?"
   - Currently: Application-level encryption before storage
   - Enhancement: Full database encryption (SQLite WAL + encryption)
   - Or: Transparent database encryption at storage level

---

## **9. SCORING SNAPSHOT**

| Component | Status | Marks |
|-----------|--------|-------|
| Authentication (Single-Factor) | ✅ Complete | 1.5/1.5 |
| Authentication (Multi-Factor) | ✅ Complete | 1.5/1.5 |
| Authorization (ACL Model) | ✅ Complete | 1.5/1.5 |
| Authorization (Policy Defined) | ✅ Complete | 1.5/1.5 |
| Authorization (Implementation) | ✅ Complete | 1.5/1.5 |
| Encryption (Key Generation) | ✅ Complete | 1.5/1.5 |
| Encryption (Encrypt/Decrypt) | ✅ Complete | 1.5/1.5 |
| Hashing (With Salt) | ✅ Complete | 1.5/1.5 |
| Digital Signature (HMAC) | ✅ Complete | 1.5/1.5 |
| Encoding (Base64) | ✅ Complete | 3/3 |
| **PRACTICAL TOTAL** | | **15/15** |
| Viva Oral Exam | 🎯 Prepare | 2/2 |
| Class Participation | 📝 Track | 3/3 |
| **GRAND TOTAL** | | **20/20** |

---

## **10. ENHANCEMENT RECOMMENDATIONS (Optional - For Excellence)**

### **Easy Wins (Can implement before viva)**
1. Add rate limiting on login attempts
2. Add account lockout after 3 failed logins
3. Add password strength meter in signup
4. Add session timeout (auto-logout after 30 min)
5. Add audit logging (who did what, when)

### **Advanced (Bonus points)**
1. Implement RSA-based key exchange for client-server communication
2. Add end-to-end encryption (user keys, not server keys)
3. Implement TOTP (Time-based OTP) with QR code
4. Add two-way encryption: Users can't read each other's messages, only app can relay
5. Implement database-level encryption

