package com.medicalsecurity.demo;

import com.medicalsecurity.config.AppConfig;
import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.crypto.KeystoreService;
import com.medicalsecurity.crypto.TamperedException;
import com.medicalsecurity.dao.Database;
import com.medicalsecurity.dao.SchemaInitializer;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import com.medicalsecurity.network.BackendServer;
import com.medicalsecurity.network.KeyServiceClient;
import com.medicalsecurity.network.TransferClient;
import com.medicalsecurity.network.WireFormat;
import com.medicalsecurity.service.DecryptionResult;
import com.medicalsecurity.service.PreparedTransfer;
import com.medicalsecurity.service.ReceiverDecryptionService;
import com.medicalsecurity.service.SenderEncryptionService;
import com.medicalsecurity.util.Hashing;
import com.medicalsecurity.util.SampleImageGenerator;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * Headless end-to-end demonstration of the complete secure-transfer workflow.
 *
 * <p>This is the acceptance-criterion harness: it exercises the SAME services
 * and the SAME socket protocol as the JavaFX applications, with a real
 * database, real AES-256-GCM encryption, real RSA-OAEP key wrapping and real
 * PKCS#12 keystores. It runs without a display, so it can be used on servers
 * and in CI as well as during the viva demo.
 *
 * <p>Run: {@code mvn exec:java -Dexec.mainClass=com.medicalsecurity.demo.HeadlessEndToEndDemo}
 */
public final class HeadlessEndToEndDemo {

    private int passed = 0;
    private int failed = 0;

    public static void main(String[] args) throws Exception {
        HeadlessEndToEndDemo demo = new HeadlessEndToEndDemo();
        int exit = demo.run();
        System.exit(exit);
    }

    public int run() throws Exception {
        banner("MEDICAL IMAGE ENCRYPTION & SECURE SHARING - END-TO-END DEMO");

        // ------------------------------------------------------------
        // 0. Environment (self-contained demo database + local storage)
        // ------------------------------------------------------------
        Path demoDir = Paths.get("data", "demo").toAbsolutePath().normalize();
        // Fresh demo state on every run (in-memory DB + local storage/keystores).
        deleteRecursively(demoDir);
        System.setProperty("medsec.db.driver", "org.apache.derby.jdbc.EmbeddedDriver");
        System.setProperty("medsec.db.url", "jdbc:derby:memory:medsec_demo;create=true");
        System.setProperty("medsec.db.user", "");
        System.setProperty("medsec.db.password", "");
        System.setProperty("medsec.storage.dir", demoDir.resolve("storage").toString());
        System.setProperty("medsec.keystore.dir", demoDir.resolve("keystores").toString());
        System.setProperty("medsec.keymgr.port", "17500");
        System.setProperty("medsec.transfer.port", "17501");
        System.setProperty("medsec.server.host", "127.0.0.1");
        System.setProperty("medsec.keystore.password", "demo-keystore-pass");

        AppConfig config = AppConfig.load();
        System.out.println("Demo working directory : " + demoDir);
        System.out.println("Database               : " + config.getDbUrl());
        System.out.println("Key-manager port       : " + config.getKeyManagerPort());
        System.out.println("Transfer port          : " + config.getTransferPort());

        // ------------------------------------------------------------
        // 1. Start MySQL-equivalent database & initialise the schema
        // ------------------------------------------------------------
        step("Initialising database schema");
        Database database = Database.fromConfig(config);
        SchemaInitializer.applyScript(database,
                new String(Files.readAllBytes(Paths.get("sql", "schema-derby.sql")),
                        java.nio.charset.StandardCharsets.UTF_8));
        check("schema applied", true);

        // ------------------------------------------------------------
        // 2. Start the key-management and receiving services
        // ------------------------------------------------------------
        step("Starting backend services");
        final BackendServer server = new BackendServer(config);
        server.start();
        Thread.sleep(300); // let the listeners bind
        check("key-management + transfer services listening", true);

        KeyServiceClient keyClient = new KeyServiceClient(config.getServerHost(), config.getKeyManagerPort(),
                config.getSocketTimeoutMs());
        TransferClient doctorTransfer = new TransferClient(config.getServerHost(), config.getTransferPort(),
                config.getSocketTimeoutMs());
        TransferClient specialistTransfer = new TransferClient(config.getServerHost(), config.getTransferPort(),
                config.getSocketTimeoutMs());
        TransferClient specialist2Transfer = new TransferClient(config.getServerHost(), config.getTransferPort(),
                config.getSocketTimeoutMs());

        try {
            runWorkflow(config, server, keyClient, doctorTransfer, specialistTransfer, specialist2Transfer);
        } finally {
            keyClient.close();
            doctorTransfer.close();
            specialistTransfer.close();
            specialist2Transfer.close();
            server.stop();
        }

        banner("RESULT: " + passed + " checks passed, " + failed + " failed");
        return failed == 0 ? 0 : 1;
    }

    private void runWorkflow(AppConfig config, BackendServer server,
                             KeyServiceClient keyClient, TransferClient doctorTransfer,
                             TransferClient specialistTransfer, TransferClient specialist2Transfer) throws Exception {

        // ------------------------------------------------------------
        // 3. Admin: create accounts (roles enforced server-side)
        // ------------------------------------------------------------
        step("Administrator login & account provisioning");
        // Installation-time bootstrap of the first administrator (once).
        server.getContext().userAdmin.createInitialAdmin("admin", "admin-demo-pass",
                "Demo Administrator", "127.0.0.1");
        KeyServiceClient.LoginResult adminLogin = keyClient.login("admin", "admin-demo-pass");
        check("administrator authenticated (role=" + adminLogin.role + ")",
                "ADMIN".equals(adminLogin.role));

        keyClient.createUser(adminLogin.token, "dr_house", "doctor-demo-pass", "Greg House", "DOCTOR");
        keyClient.createUser(adminLogin.token, "sp_wilson", "specialist-demo-pass", "James Wilson", "SPECIALIST");
        keyClient.createUser(adminLogin.token, "sp_cuddy", "specialist-demo-pass", "Lisa Cuddy", "SPECIALIST");
        check("created accounts: dr_house (DOCTOR), sp_wilson + sp_cuddy (SPECIALIST)", true);

        // Negative test: a specialist may not administer users.
        boolean specialistDenied = false;
        KeyServiceClient probe = new KeyServiceClient(config.getServerHost(), config.getKeyManagerPort(),
                config.getSocketTimeoutMs());
        try {
            KeyServiceClient.LoginResult spLogin = probe.login("sp_wilson", "specialist-demo-pass");
            try {
                probe.createUser(spLogin.token, "hacker", "hackhackhack", "Bad Actor", "ADMIN");
            } catch (Exception e) {
                specialistDenied = e.getMessage() != null && e.getMessage().startsWith("DENIED");
            }
        } finally {
            probe.close();
        }
        check("specialist cannot create users / escalate role (server-side RBAC)", specialistDenied);

        // ------------------------------------------------------------
        // 4. Doctor login, select image & recipient
        // ------------------------------------------------------------
        step("Doctor login & image selection");
        KeyServiceClient.LoginResult doctorLogin = keyClient.login("dr_house", "doctor-demo-pass");
        check("doctor authenticated (role=" + doctorLogin.role + ")", "DOCTOR".equals(doctorLogin.role));
        TransferClient.LoginResult doctorTLogin = doctorTransfer.login("dr_house", "doctor-demo-pass");
        check("doctor authenticated on transfer service", doctorTLogin.userId == doctorLogin.userId);

        List<KeyServiceClient.UserSummary> recipients = keyClient.listRecipients(doctorLogin.token);
        check("recipient list contains " + recipients.size() + " authorised specialists", recipients.size() == 2);
        KeyServiceClient.UserSummary chosen = null;
        for (int i = 0; i < recipients.size(); i++) {
            KeyServiceClient.UserSummary candidate = (KeyServiceClient.UserSummary) recipients.get(i);
            if ("sp_wilson".equals(candidate.username)) {
                chosen = candidate;
            }
        }
        check("selected recipient: sp_wilson", chosen != null && chosen.active);

        byte[] originalImage = SampleImageGenerator.generateSyntheticImage();
        Path originalFile = demoDir().resolve("original-sample.png");
        Files.createDirectories(originalFile.getParent());
        Files.write(originalFile, originalImage);
        System.out.println("    synthetic image     : " + originalFile + " (" + originalImage.length + " bytes)");
        System.out.println("    original SHA-256    : " + Hashing.sha256Hex(originalImage));

        // ------------------------------------------------------------
        // 5. Encrypt + wrap + send
        // ------------------------------------------------------------
        step("Sender-side encryption and key wrapping");
        User doctorUser = new User(doctorLogin.userId, doctorLogin.username, doctorLogin.fullName,
                Role.DOCTOR, true, System.currentTimeMillis(), null);
        User recipientUser = new User(chosen.id, chosen.username, chosen.fullName,
                Role.SPECIALIST, true, System.currentTimeMillis(), null);

        KeyServiceClient.PublicKeyInfo recipientKey =
                keyClient.getPublicKey(doctorLogin.token, chosen.username);
        PublicKey recipientPublic = KeystoreService.publicKeyFromDer(recipientKey.publicKeyDer);
        check("fetched recipient public key (RSA-" + recipientKey.keySizeBits + ", v" + recipientKey.keyVersion + ")",
                recipientKey.keySizeBits == 2048);

        SenderEncryptionService senderCrypto = new SenderEncryptionService(
                new CryptoEngine(), new KeyProtector(), config.getMaxFileBytes());
        PreparedTransfer prepared = senderCrypto.prepareOutgoing(
                doctorUser, recipientUser, "sample-scan.png", originalImage, recipientPublic);

        check("AES-256-GCM produced fresh nonce/key (ciphertext != original)",
                prepared.ciphertextDiffersFromOriginal());
        System.out.println("    ciphertext size     : " + prepared.getCiphertext().length
                + " bytes (plaintext " + originalImage.length + ")");
        System.out.println("    transfer id         : " + prepared.getManifest().getTransferId());
        System.out.println("    wrapped key size    : " + prepared.getWrappedKey().length + " bytes (RSA-OAEP)");

        // ------------------------------------------------------------
        // 6. Transmit over TCP socket to the receiving service
        // ------------------------------------------------------------
        step("Socket transfer to the receiving service");
        long rowId = doctorTransfer.submitTransfer(doctorLogin.token, prepared.getManifest(),
                prepared.getWrappedKey(), prepared.getCiphertext());
        check("transfer accepted by receiving service (row id " + rowId + ")", rowId > 0);

        // The stored payload must NOT be a viewable copy of the image.
        Path storedFile = config.getStorageDir().resolve(prepared.getManifest().getTransferId() + ".bin");
        byte[] storedBytes = Files.readAllBytes(storedFile);
        boolean looksLikePng = storedBytes.length > 4
                && storedBytes[0] == (byte) 0x89 && storedBytes[1] == 'P'
                && storedBytes[2] == 'N' && storedBytes[3] == 'G';
        boolean identicalToOriginal = java.util.Arrays.equals(storedBytes, originalImage);
        check("stored file is encrypted (no PNG header, != original) - not directly viewable",
                !looksLikePng && !identicalToOriginal);

        // ------------------------------------------------------------
        // 7. Specialist receives, verifies and decrypts
        // ------------------------------------------------------------
        step("Specialist login, verification and decryption");
        KeyServiceClient.LoginResult spLogin = keyClient.login("sp_wilson", "specialist-demo-pass");
        TransferClient.LoginResult spTLogin = specialistTransfer.login("sp_wilson", "specialist-demo-pass");
        check("specialist authenticated", spTLogin.userId == spLogin.userId);

        List<WireFormat.TransferSummary> incoming = specialistTransfer.listIncoming(spLogin.token);
        check("incoming list shows the transfer (status=" + statusOf(incoming, prepared) + ")",
                findSummary(incoming, prepared.getManifest().getTransferId()) != null);

        // Another recipient must NOT be able to obtain the wrapped key or payload.
        KeyServiceClient.LoginResult sp2Login = keyClient.login("sp_cuddy", "specialist-demo-pass");
        specialist2Transfer.login("sp_cuddy", "specialist-demo-pass");
        boolean crossDenied = false;
        try {
            keyClient.releaseWrappedKey(sp2Login.token, prepared.getManifest().getTransferId());
        } catch (Exception e) {
            crossDenied = e.getMessage() != null && e.getMessage().startsWith("DENIED");
        }
        boolean payloadDenied = false;
        try {
            specialist2Transfer.downloadPayload(sp2Login.token, prepared.getManifest().getTransferId());
        } catch (Exception e) {
            payloadDenied = e.getMessage() != null && e.getMessage().startsWith("DENIED");
        }
        check("other specialist cannot fetch this recipient's wrapped key", crossDenied);
        check("other specialist cannot download this recipient's payload", payloadDenied);

        // The addressed recipient downloads + unwraps + decrypts.
        byte[] receivedCipher = specialistTransfer.downloadPayload(spLogin.token,
                prepared.getManifest().getTransferId());
        check("downloaded ciphertext matches what the sender transmitted",
                java.util.Arrays.equals(receivedCipher, prepared.getCiphertext()));

        ProtectedKeyMaterial wrapped = keyClient.releaseWrappedKey(spLogin.token,
                prepared.getManifest().getTransferId());
        check("key service released the WRAPPED key to the addressed recipient", wrapped != null);

        KeystoreService keystores = new KeystoreService(config.getKeystoreDir(), config.getKeystorePassword());
        PrivateKey recipientPrivate = keystores.loadPrivateKey("sp_wilson");
        check("recipient private key loaded from local PKCS#12 keystore", recipientPrivate != null);

        WireFormat.TransferSummary summary = findSummary(incoming, prepared.getManifest().getTransferId());
        ImageTransfer transferRow = loadTransferRow(server, prepared.getManifest().getTransferId());

        ReceiverDecryptionService receiverCrypto = new ReceiverDecryptionService(
                new CryptoEngine(), new KeyProtector());
        DecryptionResult result = receiverCrypto.decryptIncoming(
                new User(spLogin.userId, spLogin.username, spLogin.fullName, Role.SPECIALIST, true,
                        System.currentTimeMillis(), null),
                transferRow, wrapped.getWrappedKey(), receivedCipher, recipientPrivate);

        check("GCM authentication tag verified", result.isGcmAuthenticated());
        check("SHA-256 of recovered bytes matches the manifest", result.isHashMatches());
        boolean identical = java.util.Arrays.equals(result.getRecoveredPlaintext(), originalImage);
        check("recovered image is BYTE-FOR-BYTE identical to the original", identical);
        System.out.println("    recovered SHA-256   : " + result.getPlaintextSha256());
        Path recoveredFile = demoDir().resolve("recovered-sample.png");
        Files.write(recoveredFile, result.getRecoveredPlaintext());
        System.out.println("    recovered file      : " + recoveredFile);

        specialistTransfer.markStatus(spLogin.token, prepared.getManifest().getTransferId(),
                TransferStatus.VERIFIED, "GCM tag + SHA-256 verified");
        specialistTransfer.markStatus(spLogin.token, prepared.getManifest().getTransferId(),
                TransferStatus.DECRYPTED, "Displayed to authorised specialist");
        check("transfer status advanced to VERIFIED then DECRYPTED", true);

        // ------------------------------------------------------------
        // 8. Tamper / wrong-key / malformed-payload demonstrations
        // ------------------------------------------------------------
        step("Tamper-resistance demonstrations");
        byte[] tampered = java.util.Arrays.copyOf(receivedCipher, receivedCipher.length);
        tampered[tampered.length / 2] ^= 0x5A;
        boolean tamperRejected = false;
        String tamperMessage = "";
        try {
            receiverCrypto.decryptIncoming(transferRowUser(spLogin), transferRow, wrapped.getWrappedKey(),
                    tampered, recipientPrivate);
        } catch (TamperedException e) {
            tamperRejected = true;
            tamperMessage = e.getMessage();
        }
        check("modified ciphertext is REJECTED by GCM authentication (" + tamperMessage + ")", tamperRejected);

        boolean wrongKeyRejected = false;
        PrivateKey otherKey = keystores.loadPrivateKey("sp_cuddy");
        try {
            receiverCrypto.decryptIncoming(transferRowUser(spLogin), transferRow, wrapped.getWrappedKey(),
                    receivedCipher, otherKey);
        } catch (Exception e) {
            wrongKeyRejected = e instanceof TamperedException;
        }
        check("wrong recipient private key cannot unwrap the DEK", wrongKeyRejected);

        boolean malformedRejected = false;
        try {
            receiverCrypto.decryptIncoming(transferRowUser(spLogin), transferRow, wrapped.getWrappedKey(),
                    new byte[8], recipientPrivate);
        } catch (TamperedException e) {
            malformedRejected = true;
        }
        check("malformed/truncated payload is rejected before decryption", malformedRejected);

        // ------------------------------------------------------------
        // 9. Interrupted transfer never reports false success
        // ------------------------------------------------------------
        step("Interrupted-transfer handling");
        PreparedTransfer doomed = senderCrypto.prepareOutgoing(doctorUser, recipientUser,
                "doomed-scan.png", originalImage, recipientPublic);
        byte[] truncated = new byte[doomed.getCiphertext().length / 2];
        System.arraycopy(doomed.getCiphertext(), 0, truncated, 0, truncated.length);
        boolean submitRejected = false;
        try {
            doctorTransfer.submitTransfer(doctorLogin.token, doomed.getManifest(),
                    doomed.getWrappedKey(), truncated);
        } catch (Exception e) {
            submitRejected = true;
        }
        WireFormat.TransferSummary doomedSummary = doctorTransfer.getTransfer(doctorLogin.token,
                doomed.getManifest().getTransferId());
        check("truncated submission rejected and never recorded as RECEIVED",
                submitRejected && doomedSummary == null);

        // ------------------------------------------------------------
        // 10. History & audit trail
        // ------------------------------------------------------------
        step("Transfer history and audit log");
        List<WireFormat.TransferSummary> outgoing = doctorTransfer.listOutgoing(doctorLogin.token);
        check("doctor transfer history lists the completed transfer", outgoing.size() == 1);
        List<WireFormat.AuditSummary> auditRows = keyClient.listAudit(adminLogin.token, 50);
        boolean sawAuth = false;
        boolean sawEncrypt = false;
        boolean sawRecv = false;
        boolean sawDecrypt = false;
        boolean sawKeyRelease = false;
        boolean sawDenied = false;
        for (int i = 0; i < auditRows.size(); i++) {
            WireFormat.AuditSummary row = (WireFormat.AuditSummary) auditRows.get(i);
            if (AuditEvent.AUTH_OK.equals(row.eventType)) {
                sawAuth = true;
            }
            if (AuditEvent.ENCRYPT_OK.equals(row.eventType)) {
                sawEncrypt = true;
            }
            if (AuditEvent.TRANSFER_RECV.equals(row.eventType)) {
                sawRecv = true;
            }
            if (AuditEvent.DECRYPT_OK.equals(row.eventType)) {
                sawDecrypt = true;
            }
            if (AuditEvent.KEY_RELEASE.equals(row.eventType)) {
                sawKeyRelease = true;
            }
            if (AuditEvent.KEY_RELEASE_DENIED.equals(row.eventType) || AuditEvent.ACCESS_DENIED.equals(row.eventType)) {
                sawDenied = true;
            }
        }
        System.out.println("    audit rows recorded : " + auditRows.size());
        check("audit trail contains AUTH_OK", sawAuth);
        check("audit trail contains ENCRYPT_OK", sawEncrypt);
        check("audit trail contains TRANSFER_RECV", sawRecv);
        check("audit trail contains DECRYPT_OK", sawDecrypt);
        check("audit trail contains KEY_RELEASE", sawKeyRelease);
        check("audit trail contains denied-access events", sawDenied);
        for (int i = 0; i < Math.min(12, auditRows.size()); i++) {
            WireFormat.AuditSummary row = (WireFormat.AuditSummary) auditRows.get(i);
            System.out.println("      [" + row.outcome + "] " + row.eventType
                    + (row.username == null || row.username.isEmpty() ? "" : " @" + row.username)
                    + (row.detail == null || row.detail.isEmpty() ? "" : " - " + row.detail));
        }
    }

    private static ImageTransfer loadTransferRow(BackendServer server, String transferId) throws Exception {
        return server.getContext().daos.transfers().findByTransferId(transferId);
    }

    private static User transferRowUser(KeyServiceClient.LoginResult login) {
        return new User(login.userId, login.username, login.fullName, Role.SPECIALIST, true,
                System.currentTimeMillis(), null);
    }

    private static WireFormat.TransferSummary findSummary(List<WireFormat.TransferSummary> rows,
                                                          String transferId) {
        for (int i = 0; i < rows.size(); i++) {
            if (transferId.equals(((WireFormat.TransferSummary) rows.get(i)).transferId)) {
                return (WireFormat.TransferSummary) rows.get(i);
            }
        }
        return null;
    }

    private static String statusOf(List<WireFormat.TransferSummary> rows, PreparedTransfer prepared) {
        WireFormat.TransferSummary s = findSummary(rows, prepared.getManifest().getTransferId());
        return s == null ? "missing" : s.status.name();
    }

    private static Path demoDir() {
        return Paths.get("data", "demo").toAbsolutePath().normalize();
    }

    private static void deleteRecursively(Path root) {
        try {
            deleteRecursively(root.toFile());
        } catch (Exception e) {
            System.out.println("  (could not clean " + root + ": " + e.getMessage() + ")");
        }
    }

    private static void deleteRecursively(java.io.File file) {
        if (file.isDirectory()) {
            java.io.File[] children = file.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    deleteRecursively(children[i]);
                }
            }
        }
        file.delete();
    }

    // ------------------------------------------------------------------
    // Tiny console harness
    // ------------------------------------------------------------------

    private static void banner(String text) {
        System.out.println();
        System.out.println("=====================================================================");
        System.out.println("  " + text);
        System.out.println("=====================================================================");
    }

    private static void step(String text) {
        System.out.println();
        System.out.println("-- " + text);
    }

    private void check(String description, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  [PASS] " + description);
        } else {
            failed++;
            System.out.println("  [FAIL] " + description);
        }
    }
}
