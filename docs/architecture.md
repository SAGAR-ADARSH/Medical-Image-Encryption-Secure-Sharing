# Architecture

## 1. Component overview

```mermaid
flowchart TB
    subgraph Client["Desktop client (JavaFX)"]
        UI["11 screens<br/>(navy/white theme)"]
        CTX["AppContext + UiTasks<br/>(background workers)"]
        UI --> CTX
    end

    subgraph Backend["Backend services (same JVM in desktop mode, separate via BackendServer)"]
        AUTH["AuthService<br/>(sessions)"]
        ADMIN["UserAdminService"]
        KMS["KeyManagementService"]
        TRANS["TransferService"]
        SEND["SenderEncryptionService"]
        RECV["ReceiverDecryptionService"]
        AUDIT["AuditService"]
    end

    subgraph Net["TCP socket services"]
        KSRV["KeyManagementServer :7500"]
        TSRV["TransferServer :7501"]
    end

    subgraph Storage["Storage"]
        DB[("MySQL 8.0<br/>users, keys, transfers,<br/>audit_logs")]
        FILES[("File storage<br/>encrypted payloads .bin")]
        KS[("PKCS#12 keystores<br/>private keys")]
    end

    CTX --> AUTH & ADMIN & KMS & TRANS & SEND & RECV
    KSRV --> KMS & AUTH & AUDIT
    TSRV --> TRANS & AUTH & AUDIT
    AUTH & ADMIN & KMS & TRANS --> DB
    TRANS --> FILES
    SEND & RECV --> KS
```

The UI never performs cryptographic or permission logic itself; it calls the
**service layer**, which is the same code the socket servers invoke. Every
`AuthorizationService.require*` check therefore runs server-side regardless of
whether the caller is local UI or a remote socket client.

## 2. Package map

| Package | Responsibility |
|---|---|
| `config` | `AppConfig`: env/properties resolution, `describe()` with redacted secrets |
| `util` | `Validation` (username/filename/size), `Hashing` (SHA-256 hex), `SecureIds` (SecureRandom tokens), `SampleImageGenerator` |
| `model` | `User`, `Role`, `ImageTransfer`, `TransferStatus`, `TransferManifest`, `AuditEvent`, `UserSession`, `ProtectedKeyMaterial`, `PublicKeyRecord` |
| `crypto` | `CryptoEngine` (AES-GCM), `KeyProtector` (RSA-OAEP wrap/unwrap), `KeystoreService` (PKCS#12), `SelfSignedCertificate`, `PasswordHasher`, payload records |
| `security` | `PathGuard` (traversal defence), `SessionManager`, `AuthorizationService`, exceptions |
| `dao` | `Database` (connections + transactions), `SchemaInitializer`, `Jdbc{User,Transfer,KeyRecord,AuditLog,PublicKey}DAO`, `DaoFactory` |
| `service` | Business logic: auth, user admin, key management, storage, transfer state machine, sender/receiver crypto flows, audit |
| `network` | Wire `Protocol` + `MessageIO` framing, `KeyManagementServer`, `TransferServer`, `ProtocolClient`, `KeyServiceClient`, `TransferClient`, `BackendServer` |
| `demo` | `HeadlessEndToEndDemo` acceptance harness |
| `ui` | JavaFX `MainApp`, `AppContext`, `UiTasks`, 11 controllers |

## 3. Wire protocol

Versioned framed protocol over TCP (see `network/Protocol`, `MessageIO`):

```
Request  : MAGIC(u16) VERSION(u8) TYPE(u8) | fields/payload | framed per message
Response : STATUS(u8) | body
```

* Max frame 32 MiB; every read is bounded (`readBoundedPayload`).
* Status codes: `OK=0, ERROR=1, AUTH_REQUIRED=2, DENIED=3, NOT_FOUND=4, BAD_REQUEST=5`.
* Key-management ops: `PING LOGIN LOGOUT GET_PUBLIC_KEY RELEASE_WRAPPED_KEY LIST_USERS
  CREATE_USER SET_USER_ACTIVE LIST_AUDIT LIST_RECIPIENTS`.
* Transfer ops: `SUBMIT LIST_INCOMING LIST_OUTGOING DOWNLOAD REJECT MARK_STATUS
  GET_TRANSFER LIST_ALL`.
* `RELEASE_WRAPPED_KEY` returns the **wrapped** DEK only, only to the addressed
  recipient, and writes a `KEY_RELEASE` (or `KEY_RELEASE_DENIED`) audit event.

## 4. Transfer data model

```mermaid
sequenceDiagram
    participant D as Doctor client
    participant KS as Key service
    participant TS as Transfer service
    participant S as Specialist client

    D->>KS: GET_PUBLIC_KEY(specialist)
    KS-->>D: RSA-2048 public key (DER)
    D->>D: AES-256-GCM encrypt (fresh DEK + nonce,<br/>manifest as AAD), wrap DEK with RSA-OAEP
    D->>TS: SUBMIT(manifest, wrapped DEK, ciphertext)
    TS->>TS: validate + store ciphertext + DB row (RECEIVED)
    S->>TS: DOWNLOAD(transferId)
    TS-->>S: ciphertext
    S->>KS: RELEASE_WRAPPED_KEY(transferId)
    KS-->>S: wrapped DEK (audited)
    S->>S: unwrap DEK (PKCS#12 private key),<br/>verify GCM tag + SHA-256, write bytes
    S->>TS: MARK_STATUS(VERIFIED, DECRYPTED)
```

State machine (enforced in `TransferStatus.canTransitionTo`, applied by
`JdbcTransferDAO.updateStatus`):

```
PENDING → ENCRYPTING → SENDING → RECEIVED → VERIFIED → DECRYPTED
   │           │           │         │
   └───────────┴───────────┴─────────┴──→ FAILED   (and RECEIVED → REJECTED)
FAILED / REJECTED are terminal.
```

An interrupted submission (socket cut mid-transfer) never reaches `RECEIVED`; the demo
and unit tests assert this explicitly.

## 5. Database schema (summary)

| Table | Purpose | Notable columns |
|---|---|---|
| `users` | accounts | `password_hash` (PBKDF2 string), `role`, `is_active` |
| `public_keys` | per-user key versions | `public_key_der` (never private), `key_version`, `keystore_ref` |
| `key_records` | wrapped DEK registry | `wrapped_key`, `wrap_algorithm`, `recipient_key_id` |
| `transfers` | transfer metadata + manifest fields | `nonce`, `plaintext_sha256`, `storage_ref`, `status` |
| `audit_logs` | append-only events | `event_type`, `outcome`, `detail`, `source_ip`, `created_at` |

Full DDL: [`../sql/schema.sql`](../sql/schema.sql).

## 6. Concurrency model

* Socket servers: thread-per-connection (`new Thread` per accept), daemon threads,
  bounded read timeouts.
* UI: all blocking work on JavaFX `Task` workers (`UiTasks.run`) — the FX thread never
  performs I/O.
* Database: short autocommit transactions via `Database.inTransaction` with rollback on
  error.

## 7. Error handling principles

* Fail closed: malformed frames, size overruns, path escapes and unauthorized access
  produce explicit error statuses and audit events, never silent success.
* Crypto failures surface as `TamperedException` with an honest message
  ("the ciphertext was modified, corrupted or the key is incorrect") — the UI shows
  errors instead of fake success notifications.
