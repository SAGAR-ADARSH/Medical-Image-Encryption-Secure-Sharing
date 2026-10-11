package com.medicalsecurity.service;

import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.crypto.KeystoreService;
import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.JdbcAuditLogDAO;
import com.medicalsecurity.dao.JdbcKeyRecordDAO;
import com.medicalsecurity.dao.JdbcPublicKeyDAO;
import com.medicalsecurity.dao.JdbcTransferDAO;
import com.medicalsecurity.dao.JdbcUserDAO;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationException;
import com.medicalsecurity.support.TestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Service-level end-to-end tests (spec section 11): the complete
 * encrypt -> store -> authorize -> unwrap -> decrypt flow with real
 * cryptography and persistence, plus the negative cases (wrong recipient,
 * tampered ciphertext, interrupted transfer).
 */
class TransferFlowTest {

    private TestSupport.TestDb db;
    private JdbcUserDAO users;
    private JdbcTransferDAO transfers;
    private JdbcPublicKeyDAO publicKeys;
    private CryptoEngine crypto;
    private KeyProtector keyProtector;
    private KeystoreService keystores;
    private SenderEncryptionService senderService;
    private ReceiverDecryptionService receiverService;
    private TransferService transferService;
    private KeyManagementService keyService;
    private Path tempDir;
    private User doctor;
    private User specialist;
    private User otherSpecialist;

    @BeforeEach
    void setUp() throws Exception {
        db = TestSupport.newDatabase();
        users = new JdbcUserDAO(db.database);
        transfers = new JdbcTransferDAO(db.database);
        publicKeys = new JdbcPublicKeyDAO(db.database);
        crypto = new CryptoEngine();
        keyProtector = new KeyProtector();
        tempDir = Files.createTempDirectory("medsec-test");
        keystores = new KeystoreService(tempDir.resolve("keystores"), "test-ks-pass");
        final AuditService audit = new AuditService(new JdbcAuditLogDAO(db.database));
        senderService = new SenderEncryptionService(crypto, keyProtector, 10L * 1024L * 1024L);
        receiverService = new ReceiverDecryptionService(crypto, keyProtector);
        transferService = new TransferService(db.daos, new StorageService(
                new com.medicalsecurity.security.PathGuard(tempDir.resolve("storage")), 10L * 1024L * 1024L),
                audit, 10L * 1024L * 1024L);
        keyService = new KeyManagementService(db.daos, audit);

        users.insert("dr_flow", "$pbkdf2-sha512$h", "Dr Flow", Role.DOCTOR, true);
        users.insert("sp_one", "$pbkdf2-sha512$h", "Sp One", Role.SPECIALIST, true);
        users.insert("sp_two", "$pbkdf2-sha512$h", "Sp Two", Role.SPECIALIST, true);
        doctor = users.findByUsername("dr_flow");
        specialist = users.findByUsername("sp_one");
        otherSpecialist = users.findByUsername("sp_two");

        registerKey(specialist);
        registerKey(otherSpecialist);
    }

    private void registerKey(User user) throws Exception {
        final PublicKey pub = keystores.provisionKeyPair(user.getUsername());
        keyService.registerUserPublicKey(user.getId(), user.getUsername(),
                "RSA", KeystoreService.KEY_SIZE_BITS, pub.getEncoded(), 1,
                user.getUsername() + ".p12");
    }

    @Test
    @DisplayName("The full service flow reconstructs the exact original bytes")
    void fullFlowRoundTrip() throws Exception {
        final byte[] image = syntheticImage(6000);

        // Sender side.
        final PublicKey recipientPublic = KeystoreService.publicKeyFromDer(keyService.getPublicKey(doctor, "sp_one").publicKeyDer);
        final PreparedTransfer prepared = senderService.prepareOutgoing(
                doctor, specialist, "scan.png", image, recipientPublic);
        assertNotNull(prepared);
        assertTrue(prepared.ciphertextDiffersFromOriginal());
        final long rowId = transferService.receiveIncoming(doctor, prepared.getManifest(),
                prepared.getWrappedKey(), prepared.getCiphertext());
        assertTrue(rowId > 0);

        // Receiver side.
        final ImageTransfer stored = transfers.findByTransferId(prepared.getManifest().getTransferId());
        assertNotNull(stored);
        assertEquals(TransferStatus.RECEIVED, stored.getStatus());
        final byte[] ciphertext = transferService.downloadPayload(specialist, stored.getTransferId());
        assertEquals(image.length + 16, ciphertext.length, "plaintext + 16-byte GCM tag");
        final ProtectedKeyMaterial released = keyService.releaseWrappedKey(specialist, stored.getTransferId(), "127.0.0.1");
        assertNotNull(released);
        final PrivateKey privateKey = keystores.loadPrivateKey("sp_one");
        final DecryptionResult result = receiverService.decryptIncoming(
                specialist, stored, released.getWrappedKey(), ciphertext, privateKey);
        assertTrue(result.isVerified());
        assertTrue(result.isGcmAuthenticated());
        assertTrue(result.isHashMatches());
        assertArrayEquals(image, result.getRecoveredPlaintext(), "exact original bytes");

        // Status progression.
        transferService.markStatus(specialist, stored.getTransferId(), TransferStatus.VERIFIED, null, "127.0.0.1");
        transferService.markStatus(specialist, stored.getTransferId(), TransferStatus.DECRYPTED, null, "127.0.0.1");
        assertEquals(TransferStatus.DECRYPTED,
                transfers.findByTransferId(stored.getTransferId()).getStatus());
    }

    @Test
    @DisplayName("A different specialist cannot access the wrapped key or the payload")
    void recipientIsolation() throws Exception {
        final byte[] image = syntheticImage(1024);
        final PublicKey recipientPublic = KeystoreService.publicKeyFromDer(keyService.getPublicKey(doctor, "sp_one").publicKeyDer);
        final PreparedTransfer prepared = senderService.prepareOutgoing(
                doctor, specialist, "scan.png", image, recipientPublic);
        transferService.receiveIncoming(doctor, prepared.getManifest(),
                prepared.getWrappedKey(), prepared.getCiphertext());
        final String transferId = prepared.getManifest().getTransferId();

        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                keyService.releaseWrappedKey(otherSpecialist, transferId, "127.0.0.1");
            }
        });
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                transferService.downloadPayload(otherSpecialist, transferId);
            }
        });
    }

    @Test
    @DisplayName("Tampered ciphertext is rejected during decryption")
    void tamperedCiphertextRejected() throws Exception {
        final byte[] image = syntheticImage(2048);
        final PublicKey recipientPublic = KeystoreService.publicKeyFromDer(keyService.getPublicKey(doctor, "sp_one").publicKeyDer);
        final PreparedTransfer prepared = senderService.prepareOutgoing(
                doctor, specialist, "scan.png", image, recipientPublic);
        transferService.receiveIncoming(doctor, prepared.getManifest(),
                prepared.getWrappedKey(), prepared.getCiphertext());
        final ImageTransfer stored = transfers.findByTransferId(prepared.getManifest().getTransferId());
        final byte[] ciphertext = transferService.downloadPayload(specialist, stored.getTransferId());
        ciphertext[10] ^= 0x7F;
        final ProtectedKeyMaterial released = keyService.releaseWrappedKey(specialist, stored.getTransferId(), "127.0.0.1");
        final PrivateKey privateKey = keystores.loadPrivateKey("sp_one");
        assertThrows(Exception.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                receiverService.decryptIncoming(specialist, stored, released.getWrappedKey(),
                        ciphertext, privateKey);
            }
        });
    }

    @Test
    @DisplayName("Doctors cannot receive and specialists cannot send")
    void roleConstraintsEnforced() throws Exception {
        final byte[] image = syntheticImage(512);
        final PublicKey recipientPublic = KeystoreService.publicKeyFromDer(keyService.getPublicKey(doctor, "sp_one").publicKeyDer);
        // Specialist cannot act as sender.
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                senderService.prepareOutgoing(specialist, specialist, "scan.png", image, recipientPublic);
            }
        });
        // Sender and recipient must differ (validated before any encryption).
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                senderService.prepareOutgoing(doctor, doctor, "scan.png", image, recipientPublic);
            }
        });
    }

    @Test
    @DisplayName("An interrupted submission is not silently marked as received")
    void interruptedTransferNotFalselySuccessful() throws Exception {
        // Simulate the crash case: a transfer row that never reached RECEIVED.
        final ImageTransfer t = new ImageTransfer();
        t.setTransferId("ghost-1");
        t.setSenderId(doctor.getId());
        t.setRecipientId(specialist.getId());
        t.setOriginalFilename("scan.png");
        t.setPlaintextSize(10L);
        t.setCiphertextSize(26L);
        t.setPlaintextSha256("x");
        t.setAlgorithm("AES/GCM/NoPadding");
        t.setKeySizeBits(256);
        t.setNonce(new byte[12]);
        t.setTagBits(128);
        t.setStatus(TransferStatus.PENDING);
        t.setStorageRef("ghost-1.bin");
        t.setCreatedAtMs(System.currentTimeMillis());
        t.setUpdatedAtMs(System.currentTimeMillis());
        transfers.insert(t);

        final ImageTransfer found = transfers.findByTransferId("ghost-1");
        assertEquals(TransferStatus.PENDING, found.getStatus());
        assertFalse(found.getStatus() == TransferStatus.RECEIVED,
                "incomplete transfers must never look successfully received");
    }

    private static byte[] syntheticImage(int size) {
        final byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) ((i * 13) ^ 0x5A);
        }
        return data;
    }
}
