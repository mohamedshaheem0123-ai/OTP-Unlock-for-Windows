# OTP-Based Laptop Authentication System

A Python + FastAPI OTP authentication system with a Windows desktop gate client.

## Public deployment

The FastAPI server is configured to listen on `0.0.0.0` when deployed and supports a public HTTPS URL.

### 1. Install
```bash
pip install -r requirements.txt
```

### 2. Create the encryption key
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Set the generated value as the `FERNET_KEY` environment variable.

### 3. Run locally
```bash
uvicorn main:app --host 0.0.0.0 --port 8001
```

Open:
`http://127.0.0.1:8001`

### 4. Deploy publicly

Use any Python hosting service that supports FastAPI. Set:
- `FERNET_KEY` = a new secret key
- `PUBLIC_URL` = your HTTPS application URL
- `DB_PATH` = a persistent database path if your host provides persistent storage

The included `Procfile` and `render.yaml` are ready for common deployments.

### 5. Configure the Windows client

For a public server, set:

```text
OTP_GATE_URL=https://your-domain.example.com/local-gate
```

The client reads this value from the environment. Do not use plain HTTP for a public server because the username, password, and OTP must be protected in transit.

## Important security notes

- Never commit `.env`, `otp_auth.db`, or other database files to a public GitHub repository.
- Generate a fresh `FERNET_KEY` for the deployed server.
- Use HTTPS for every public deployment.
- SQLite is suitable for a prototype. For a production multi-instance deployment, use a managed database.
- This project is an application-level authentication gate; it does not replace the native Windows sign-in screen.
