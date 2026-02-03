# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Node.js/Express Certificate Authority (CA) webserver for SPL Pathology Associates. It handles automatic SSL/TLS certificate renewal for organization applications using Windows-based Certificate Authority infrastructure through a web API.

**Tech Stack:** Node.js, Express.js, SQLite3 (better-sqlite3), jsrsasign, node-cron, Twilio

## Commands

```bash
npm start          # Start server with --watch flag for auto-reload
npm run dev        # Same as npm start
node backend/sqlite/db_cli.js   # Interactive admin CLI for database management
```

The server runs on ports 80 (HTTP redirect) and 443 (HTTPS). Requires Windows environment with CA tools (certreq.exe, certutil.exe) and OpenSSL on PATH.

## Architecture

```
backend/
├── controller/     # Business logic
│   ├── ca-tools.js      # Certificate renewal/registration logic
│   ├── spawn.js         # Windows certreq/certutil command execution
│   ├── selfCheck.js     # Certificate validation and CSR generation
│   ├── cron.js          # Scheduled tasks (daily expiration checks)
│   ├── textIT.js        # Twilio SMS notifications
│   └── ca-bundle.js     # Mozilla CA bundle management
├── routes/
│   └── api.js           # Express routes (/api/renew, /api/register)
└── sqlite/
    ├── db.js            # Database schema and CRUD operations
    └── db_cli.js        # Interactive CLI for admin management
```

**Entry Point:** `server.js` - Handles startup, SSL certificate self-renewal, HTTPS setup, and cron initialization.

## API Endpoints

- `POST /api/renew` - Renews existing certificate (requires base64-encoded CSR in `req` field)
- `POST /api/register` - Registers new certificate for auto-renewal (requires `pemCertText` and `hexSignature`)
- `GET /CA.pem`, `/CA.cer`, `/CA.crt`, `/CA.der` - CA certificate in various formats
- `GET /{CA_PEM_BUNDLE_ROUTE}` - Combined CA bundle (SPL CA + Mozilla Firefox CAs)

## Database

SQLite database (`Certificates.db`) with two tables:
- `CertificatesInfo` - Registered certificates with public key, expiration, approval flags
- `IT_Text_Logs` - SMS notification history

Key fields use string booleans ("true"/"false"). The `db.js` module handles type casting.

## Certificate Lifecycle

1. **Registration:** Client submits cert via `/api/register` → Server verifies CA signature → Creates pending record → Admin approves via `db_cli.js`
2. **Renewal:** Client submits CSR via `/api/renew` → Server validates CSR against registered cert → If <14 days to expiration and validations pass → Submit to Windows CA → Return signed certificate
3. **Self-renewal:** On startup, server checks its own SSL cert and auto-renews if <14 days from expiration using config from `/certs/{SERVICE_NAME}.cfg`

## Key Patterns

- Standard response object: `{ isError: boolean, msg: string, data?: any }`
- All requests assigned unique UUID (eventId) for log tracing
- Windows CA integration via `certreq.exe` (submit CSR) and `certutil.exe` (sign/retrieve)
- Admin approval workflow: changes to IP, subject, or altNames require `updateIP`, `updateSubjectStr`, `updateAltNames`, or `approveAll` flags

## Configuration

Required environment variables (see `.env template`):
- `SSL_KEY_PATH`, `SSL_CERT_PATH` - HTTPS credentials
- `SSL_CA_PEM_PATH`, `SSL_CA_CER_PATH` - CA certificate paths
- `SERVICE_NAME` - Service identifier
- `TWILIO_PHONE_NUMBER`, `IT_PHONE`, `ACCOUNTSID`, `AUTH_TOKEN` - Twilio SMS config
