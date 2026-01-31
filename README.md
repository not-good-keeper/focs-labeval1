Secure Chat — improved

What changed
- Replaced polling/form-only messaging with realtime WebSockets using Flask-SocketIO (Eventlet).
- Improved `groupchat` and `dmchat` UIs using Bootstrap and client Socket.IO code.
- Safer SQLite connections via `get_db()` and a `fetch_messages()` helper that decrypts and verifies messages server-side.
- Added `requirements.txt` and run instructions.

Run
1. (Optional) create or migrate DB: `python db.py` then `python createadmindb.py`
2. Install deps:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
python app.py
```

Notes
- OTP currently prints to console (demo). Replace with real delivery for production.
- Secrets and keys are file-based for convenience; move to env or secrets manager for production.
- For reliability with many clients, consider moving messages to a dedicated DB server and using Redis for Socket.IO message queue/backing store.
