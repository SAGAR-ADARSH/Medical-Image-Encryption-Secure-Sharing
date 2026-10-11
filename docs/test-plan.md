# Test Plan

## 1. How to run

```bash
mvn clean test                                              # JUnit 5 suite (10 classes / 47 cases)
mvn compile exec:java -Dexec.mainClass=com.medicalsecurity.demo.HeadlessEndToEndDemo
```

The unit suite runs against an **in-memory Derby database** through the same DAO layer
the MySQL deployment uses (only the JDBC URL differs), so tests are self-contained and
repeatable. The end-to-end demo additionally exercises the real TCP socket protocol
(ports 17500/17501) and file storage.

## 2. Test-case matrix (spec section 11)

| # | Spec test area | Test class / harness | Key assertions |
|---|---|---|---|
| 1 | Cryptographic engine (encrypt/decrypt) | `CryptoEngineTest` (7 cases) | exact-byte round trip; fresh key/nonce per encryption; tampered ciphertext → `TamperedException`; wrong key rejected; malformed payloads rejected; nonce/key uniqueness; AAD covered by GCM tag |
| 2 | Key wrapping | `KeyProtectorTest` (3 cases) | wrap/unwrap round trip; wrong private key fails; wrapped output contains no raw DEK; RSA-2048 parameters |
| 3 | Password hashing | `PasswordHasherTest` (3 cases) | salted unique hashes; plaintext absent from hash; verify semantics; empty password rejected |
| 4 | Path traversal defence | `PathGuardTest` (4 cases) | in-root paths allowed; `../` traversal, NUL bytes, empty refs rejected; `requireInside` detects escapes |
| 5 | Role-based authorization | `AuthorizationTest` (7 cases) | only DOCTOR sends; only SPECIALIST receives; ADMIN-only functions; sender/recipient-only access; forgery of sender identity rejected; inactive users rejected |
| 6 | Transfer state machine | `TransferStatusTest` (4 cases) | legal lifecycle; skip/backwards jumps forbidden; terminal states; string round trip |
| 7 | User persistence (DB) | `UserDaoTest` (4 cases) | insert/find; duplicate username rejected; active toggle; role filter |
| 8 | Transfer persistence (DB) | `TransferDaoTest` (4 cases) | insert/query by parties; status transitions persisted; unrecorded submissions never listed; `markReceived` metadata |
| 9 | Authentication service | `AuthServiceTest` (5 cases) | login success/failure; disabled accounts; AUTH_OK/AUTH_FAIL audited; session lifecycle + logout |
| 10 | End-to-end service flow | `TransferFlowTest` (5 cases) | full encrypt→store→unwrap→decrypt exact bytes; recipient isolation (wrapped key + payload); tampered ciphertext rejected; role constraints; interrupted transfer never falsely received |

## 3. End-to-end acceptance demo (`HeadlessEndToEndDemo`)

35 checks across 8 stages — this is the acceptance criterion of the project:

1. Schema application on a fresh database.
2. Backend services listening (key-management + transfer, real sockets).
3. Admin login + account provisioning (doctor + 2 specialists) + **negative RBAC**
   (specialist cannot create users).
4. Doctor login, recipient listing, synthetic PNG generation (SHA-256 recorded).
5. Sender-side encryption: fresh AES-256-GCM key/nonce, ciphertext ≠ plaintext,
   RSA-OAEP wrapped key (256 bytes), unique transfer id.
6. Socket submission: stored file is encrypted (no PNG header), DB row created.
7. Specialist login: incoming list shows RECEIVED; **other specialist is denied** the
   wrapped key and the payload; downloaded ciphertext equals what was sent; key service
   releases the wrapped key to the addressed recipient only; PKCS#12 private key loads;
   **GCM tag verified**; SHA-256 matches; **recovered image byte-for-byte identical**;
   status advances VERIFIED → DECRYPTED.
8. Tamper resistance: modified ciphertext → `TamperedException`; wrong private key →
   unwrap failure; malformed payload rejected; truncated submission never recorded as
   RECEIVED; history + audit assertions (AUTH_OK, ENCRYPT_OK, TRANSFER_RECV, DECRYPT_OK,
   KEY_RELEASE, denied-access events).

## 4. Manual UI test script

1. `mvn javafx:run`, log in as admin → all admin screens visible; as doctor → send/outbox
   visible, user management hidden; as specialist → inbox/verify visible.
2. Doctor: send a PNG to a specialist → outbox shows status progression.
3. Specialist: verify & decrypt → save file → compare bytes with the original
   (`sha256sum`).
4. Negative: open the stored `.bin` in an image viewer → must not display; alter one
   byte → verify step must fail.
5. Kill the client mid-send → transfer must not appear as RECEIVED.

## 5. Coverage notes and known gaps

* All service-layer permission checks have at least one positive and one negative test.
* The socket protocol is covered by the demo (happy path + denial + truncation).
* Not covered: TLS handshake paths (require certificate provisioning), UI pixel-level
  tests (manual script above), MySQL-specific SQL behaviour (schema is standard SQL;
  DAOs run on Derby in CI). Fuzzing of the frame parser is out of scope.
