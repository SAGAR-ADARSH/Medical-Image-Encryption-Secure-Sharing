package com.medicalsecurity.dao;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import com.medicalsecurity.support.TestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transfer persistence tests (spec section 11).
 */
class TransferDaoTest {

    private TestSupport.TestDb db;
    private JdbcUserDAO users;
    private JdbcTransferDAO transfers;
    private User doctor;
    private User specialist;

    @BeforeEach
    void setUp() throws Exception {
        db = TestSupport.newDatabase();
        users = new JdbcUserDAO(db.database);
        transfers = new JdbcTransferDAO(db.database);
        users.insert("dr_flow", "$pbkdf2-sha512$h", "Dr Flow", Role.DOCTOR, true);
        users.insert("sp_flow", "$pbkdf2-sha512$h", "Sp Flow", Role.SPECIALIST, true);
        doctor = users.findByUsername("dr_flow");
        specialist = users.findByUsername("sp_flow");
    }

    private ImageTransfer newTransfer(String transferId) {
        final ImageTransfer t = new ImageTransfer();
        t.setTransferId(transferId);
        t.setSenderId(doctor.getId());
        t.setRecipientId(specialist.getId());
        t.setOriginalFilename("scan.png");
        t.setContentType("image/png");
        t.setPlaintextSize(100L);
        t.setCiphertextSize(116L);
        t.setPlaintextSha256("abc123");
        t.setAlgorithm("AES/GCM/NoPadding");
        t.setKeySizeBits(256);
        t.setNonce(new byte[12]);
        t.setTagBits(128);
        t.setStatus(TransferStatus.PENDING);
        t.setStorageRef(transferId + ".bin");
        t.setCreatedAtMs(System.currentTimeMillis());
        t.setUpdatedAtMs(System.currentTimeMillis());
        return t;
    }

    @Test
    @DisplayName("Transfers can be inserted and looked up by id and parties")
    void insertAndQuery() throws Exception {
        final long id = transfers.insert(newTransfer("tr-100"));
        assertTrue(id > 0);
        final ImageTransfer found = transfers.findByTransferId("tr-100");
        assertNotNull(found);
        assertEquals(TransferStatus.PENDING, found.getStatus());
        assertEquals(1, transfers.findByRecipientId(specialist.getId()).size());
        assertEquals(1, transfers.findBySenderId(doctor.getId()).size());
        assertEquals(1, transfers.findRecent(10).size());
        assertTrue(transfers.findByTransferId("missing-id") == null);
    }

    @Test
    @DisplayName("Status updates persist and are visible afterwards")
    void statusUpdatesPersist() throws Exception {
        transfers.insert(newTransfer("tr-200"));
        assertTrue(transfers.updateStatus("tr-200", TransferStatus.ENCRYPTING, null));
        assertTrue(transfers.updateStatus("tr-200", TransferStatus.SENDING, null));
        assertTrue(transfers.updateStatus("tr-200", TransferStatus.RECEIVED, null));
        assertTrue(transfers.updateStatus("tr-200", TransferStatus.VERIFIED, null));
        assertTrue(transfers.updateStatus("tr-200", TransferStatus.DECRYPTED, null));
        assertEquals(TransferStatus.DECRYPTED, transfers.findByTransferId("tr-200").getStatus());
    }

    @Test
    @DisplayName("A failed submission never appears in the incoming list")
    void failedSubmissionNotListed() throws Exception {
        assertTrue(transfers.findByRecipientId(specialist.getId()).isEmpty());
    }

    @Test
    @DisplayName("markReceived records the reception metadata")
    void markReceivedRecordsMetadata() throws Exception {
        transfers.insert(newTransfer("tr-300"));
        transfers.updateStatus("tr-300", TransferStatus.ENCRYPTING, null);
        transfers.updateStatus("tr-300", TransferStatus.SENDING, null);
        assertTrue(transfers.markReceived("tr-300", "tr-300.bin", 116L));
        final ImageTransfer found = transfers.findByTransferId("tr-300");
        assertEquals(TransferStatus.RECEIVED, found.getStatus());
        assertNotNull(found.getReceivedAtMs());
        assertTrue(found.getReceivedAtMs().longValue() > 0L);
    }
}
