# Medical Image Encryption & Secure Sharing

A college-level Java desktop project for **encrypting medical images and sharing them
securely between hospital roles**. Doctors encrypt and send images; specialists receive,
verify and decrypt them; administrators manage accounts, keys and audit logs.

> **Scope statement (honest):** this is an academic project demonstrating correct
> application of standard cryptography and a client–server design. It is **not
> production-ready** and no clinical system should use it as-is. See
> [Limitations](#limitations).

---

## Abstract

Medical images (X-rays, MRIs, CT scans) travel between doctors, radiology specialists
and hospitals. Storing or sending them in plaintext exposes patient privacy. This
project implements a desktop application in which every transferred image is encrypted
with **AES-256-GCM** using a fresh data key and a unique 96-bit nonce per transfer. The
data key is wrapped for the **individual recipient** with their **RSA-2048** public key
(RSA-OAEP), so only that recipient's private key — kept in a local **PKCS#12** keystore —
can unwrap it. Ciphertext, wrapped keys, transfer metadata and audit events are stored
in **MySQL 8.0** through JDBC; the ciphertext itself is kept on the file server side and
is never viewable without decryption. Images travel over **TCP sockets** (framed JSON
metadata + binary payload) between the desktop client and the backend services. Role
permissions (ADMIN / DOCTOR / SPECIALIST) are enforced **server-side**, and every
security-relevant action is written to an append-only audit log.

## Feature overview

| Area | Implemented |
|---|---|
| UI | JavaFX desktop app, 11 screens, navy/white theme (login, dashboard, send, outbox, inbox, verify & decrypt, user management, key management, audit log, transfer history, settings) |
| Crypto | AES-256-GCM (12-byte nonce, 128-bit tag) via JCE; RSA-2048 OAEP-SHA256 key wrapping; PBKDF2-HMAC-SHA512 (120k iterations) password hashing with per-user salts; SHA-256 integrity hashes |
| Keys | Per-user PKCS#12 keystores (`<username>.p12`), self-signed certificate carrying the public key; DB stores public keys + wrapped DEKs only; plaintext keys never stored or logged |
| Backend | Key-management service + transfer service over TCP sockets (single in-process instance for the desktop setup, standalone `BackendServer` for two-machine use); framed protocol with size caps |
| Database | MySQL 8.0 schema (`sql/schema.sql`); identical DAO layer runs on Apache Derby in-memory for tests/demo (`sql/schema-derby.sql`) |
| Security | Server-side RBAC, path-traversal guard, authentication sessions, transfer state machine (PENDING → ENCRYPTING → SENDING → RECEIVED → VERIFIED → DECRYPTED), audit log for auth/key/encrypt/decrypt/denied events |
| Tests | JUnit 5 suite (10 test areas, 47 test cases) + headless end-to-end demo with 35 checks |

## Project structure

```
Medical-Image-Encryption-Secure-Sharing/
├── pom.xml                     Maven build (Java 21, JavaFX 21, JUnit 5, MySQL Connector/J, Derby)
├── sql/
│   ├── schema.sql              MySQL 8.0 schema script
│   └── schema-derby.sql        Equivalent schema for tests/demo (Derby)
├── scripts/
│   └── offline-build.sh        Optional offline compile/test harness (sandbox)
├── docs/
│   ├── architecture.md         Architecture, protocols, data flow
│   ├── security-design.md      Threat model, crypto design, guarantees & non-guarantees
│   ├── test-plan.md            Test matrix and how to run everything
│   └── academic-report.md      Full academic report (abstract → conclusion)
└── src/
    ├── main/java/com/medicalsecurity/
    │   ├── config/             AppConfig (env + properties)
    │   ├── util/               Validation, hashing, secure ids, sample image generator
    │   ├── model/              User, Role, ImageTransfer, TransferManifest, AuditEvent, ...
    │   ├── crypto/             CryptoEngine, KeyProtector, KeystoreService, PasswordHasher,
    │   │                       SelfSignedCertificate, EncryptedPayload, TamperedException
    │   ├── security/           PathGuard, SessionManager, AuthorizationService
    │   ├── dao/                Database, SchemaInitializer, Jdbc*DAO, DaoFactory
    │   ├── service/            Auth, UserAdmin, KeyManagement, Storage, Transfer,
    │   │                       SenderEncryption, ReceiverDecryption, Audit, AdminBootstrap
    │   ├── network/            Protocol, MessageIO, KeyManagementServer, TransferServer,
    │   │                       ProtocolClient, KeyServiceClient, TransferClient, BackendServer
    │   ├── demo/               HeadlessEndToEndDemo (acceptance harness)
    │   └── ui/                 MainApp, AppContext, UiTasks + 11 screen controllers
    ├── main/resources/         fxml/ (11 screens), css/styles.css, sql/ (schema copies)
    └── test/java/              10 JUnit 5 test classes + TestSupport
```

## Requirements

| Component | Version |
|---|---|
| JDK | 17 or 21 LTS (21 recommended) |
| Maven | 3.8+ |
| MySQL | 8.0+ |
| JavaFX | 21.0.2 (pulled in by Maven) |
| OS | Linux Mint 21/22 (instructions below), any OS with the above |

## Setup on Linux Mint

### 1. Install Java 21, Maven, MySQL 8

```bash
sudo apt update
sudo apt install openjdk-21-jdk maven mysql-server-8.0
java -version     # should show 21
mvn -version
```

If your Mint release ships MySQL 5.7/MariaDB, install MySQL 8.0 from Oracle's apt repo
or use the official `mysql-server-8.0` package.

### 2. Create the database and user

```bash
sudo mysql -u root
```

```sql
CREATE DATABASE medsec_db CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'medsec'@'localhost' IDENTIFIED BY 'ChangeMe-Strong-Pass!';
GRANT ALL PRIVILEGES ON medsec_db.* TO 'medsec'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Apply the schema (from the project root):

```bash
mysql -u medsec -p medsec_db < sql/schema.sql
```

### 3. Configure

Defaults work for the local demo (`jdbc:mysql://localhost:3306/medsec_db`). Override via
environment variables or `medsec.properties` (see `AppConfig`):

| Variable | Default | Meaning |
|---|---|---|
| `MEDSEC_DB_URL` | `jdbc:mysql://localhost:3306/medsec_db` | JDBC URL |
| `MEDSEC_DB_USER` | `medsec` | DB user |
| `MEDSEC_DB_PASSWORD` | *(empty)* | DB password |
| `MEDSEC_STORAGE_DIR` | `data/storage` | encrypted payload storage |
| `MEDSEC_KEYSTORE_DIR` | `data/keystores` | PKCS#12 keystores |
| `MEDSEC_KEYSTORE_PASSWORD` | `medsec-keystore-pass` | keystore password (demo default) |
| `MEDSEC_SERVER_HOST` | `localhost` | bind/connect host |
| `MEDSEC_KEY_MANAGER_PORT` | `7500` | key-management service |
| `MEDSEC_TRANSFER_PORT` | `7501` | transfer service |
| `MEDSEC_MAX_FILE_BYTES` | `26214400` | 25 MiB upload cap |
| `MEDSEC_TLS_ENABLED` | `false` | TLS between client and services |

> The keystore and DB passwords above are **demo defaults for local use**; change them
> for anything shared. Plaintext keys are never placed in the database or logs even
> with default passwords.

### 4. Run

```bash
# Build & test
mvn clean test

# Desktop application (starts the in-process key-manager + transfer services too)
mvn javafx:run

# Standalone backend (two-machine setup / headless server)
mvn compile exec:java -Dexec.mainClass=com.medicalsecurity.network.BackendServer

# Create the first administrator (writes audit event + admin PKCS#12 keystore)
mvn compile exec:java -Dexec.mainClass=com.medicalsecurity.service.AdminBootstrap \
    -Dexec.args="admin 'YourAdminPass!23' 'System Administrator'"

# Headless end-to-end acceptance demo (Derby in-memory DB, ports 17500/17501)
mvn compile exec:java -Dexec.mainClass=com.medicalsecurity.demo.HeadlessEndToEndDemo
```

First login: **admin** / the password you gave `AdminBootstrap`. Create doctor and
specialist accounts from *User Management*; each new account gets a PKCS#12 keystore
created in `data/keystores/`.

### Two-machine deployment

Machine A runs `BackendServer` + MySQL. Machine B runs the desktop app with
`MEDSEC_SERVER_HOST=<machine-A>`. The administrator copies each newly provisioned
`<username>.p12` to the recipient's machine over a trusted channel (like handing over
an encrypted USB key) — private keys are never sent through this application's protocol.

## Testing

```bash
mvn test                       # JUnit 5 suite: 10 test classes / 47 cases
mvn exec:java -Dexec.mainClass=com.medicalsecurity.demo.HeadlessEndToEndDemo
```

The end-to-end demo performs the acceptance scenario: doctor encrypts a synthetic PNG →
sends over real TCP sockets → specialist downloads, unwraps the DEK with the keystore
private key, decrypts → **recovered bytes are identical** (SHA-256 compared) → tampered
ciphertext is rejected → wrong-recipient access is denied → interrupted transfers never
show as received → audit log contains the expected events. Details in
[docs/test-plan.md](docs/test-plan.md).

## How the transfer works (short version)

1. Doctor selects an image + specialist recipient. The client asks the key service for
   the recipient's RSA public key.
2. The sender generates a random AES-256 key (DEK) and a unique 96-bit nonce, encrypts
   the image with **AES-256-GCM** and uses the transfer manifest as GCM additional
   authenticated data (metadata is authenticated too).
3. The DEK is wrapped with the recipient's RSA-2048 public key (OAEP-SHA256).
4. The client submits `manifest + wrapped DEK + ciphertext` to the transfer service over
   a framed TCP socket. The server stores the ciphertext on disk and the metadata +
   wrapped DEK in MySQL (never the plaintext DEK).
5. The specialist downloads the payload and requests the wrapped DEK from the key
   service (audited `KEY_RELEASE`). Only the addressed recipient is served.
6. The specialist's client unwraps the DEK with the private key from their PKCS#12
   keystore, verifies the GCM tag and the SHA-256 hash, and writes the exact original
   bytes. Any tampering breaks the GCM tag and decryption is refused.

## Limitations (explicit)

- **Not production-ready.** Academic scope: single hospital, trusted LAN assumptions,
  no HA, no backup strategy, no formal key ceremony.
- **TLS is optional and off by default** (`MEDSEC_TLS_ENABLED=false` binds plain TCP for
  the localhost demo). On a real network, enable TLS and provision truststores.
- **MySQL is required for the app**; the sandbox development environment used an
  in-memory Derby database with the same DAO layer for tests/demo only. The schema
  shipped for MySQL is `sql/schema.sql`.
- **Password recovery does not exist** — an administrator resets accounts by creating
  new credentials; forgotten keystore passwords require re-provisioning the key pair.
- The self-signed certificates inside the PKCS#12 files are public-key containers for
  the keystore format; this project does **not** build a PKI or a trust hierarchy.
- The JavaFX UI must be run on a machine with a display. The acceptance demo is
  headless by design.
- No mobile/web clients; no DICOM parsing (the pipeline treats the image as bytes and
  preserves any format).
- Audit logs are append-only at the application layer; a DB administrator can still
  modify tables directly (no external log shipping / WORM storage).

## License

Academic/educational use. See repository license file if present.
