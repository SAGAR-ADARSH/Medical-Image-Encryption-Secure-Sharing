package com.medicalsecurity.service;

import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.dao.DaoFactory;
import com.medicalsecurity.dao.PublicKeyRecord;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.TransferManifest;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationService;
import com.medicalsecurity.util.Validation;

import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

/**
 * Server-side transfer orchestration: receiving encrypted payloads from
 * senders, serving them to addressed recipients, and recording the transfer
 * lifecycle in the database. Client-side crypto lives in
 * {@link SenderEncryptionService} / {@link ReceiverDecryptionService}.
 *
 * <p>Every method re-checks identity and role permissions: the protocol never
 * trusts client-supplied sender/recipient identifiers or authorization flags.
 */
public final class TransferService {

    private final DaoFactory daos;
    private final StorageService storage;
    private final AuditService audit;
    private final long maxFileBytes;

    public TransferService(DaoFactory daos, StorageService storage, AuditService audit, long maxFileBytes) {
        this.daos = daos;
        this.storage = storage;
        this.audit = audit;
        this.maxFileBytes = maxFileBytes;
    }

    /**
     * Receives one transfer over the socket protocol. The sender identity is
     * taken from the authenticated session and cross-checked against the
     * manifest; the client cannot claim someone else's identity.
     */
    public long receiveIncoming(User authenticatedSender, TransferManifest manifest,
                                byte[] wrappedKey, byte[] ciphertext) throws SQLException, IOException {
        try {
            AuthorizationService.requireSenderIdentity(authenticatedSender, manifest.getSenderUserId());
        } catch (RuntimeException e) {
            audit.denied(AuditEvent.ACCESS_DENIED, authenticatedSender.getUsername(),
                    Long.valueOf(authenticatedSender.getId()), manifest.getTransferId(),
                    "Sender identity mismatch", null);
            throw e;
        }
        manifest.validate();
        if (ciphertext == null || ciphertext.length != manifest.getCiphertextSize()) {
            throw new IOException("Ciphertext size does not match the manifest");
        }
        if (wrappedKey == null || wrappedKey.length == 0 || wrappedKey.length > 1024) {
            throw new IOException("Invalid wrapped key material");
        }
        if (ciphertext.length > maxFileBytes) {
            throw new IOException("Payload exceeds the configured maximum size");
        }

        // Recipient must exist, be active and be allowed to receive.
        User recipient = daos.users().findById(manifest.getRecipientUserId());
        if (recipient == null) {
            throw new IOException("Unknown recipient");
        }
        AuthorizationService.requireCanReceive(recipient);
        if (!recipient.getUsername().equals(manifest.getRecipientUsername())) {
            throw new IOException("Recipient username does not match the recipient id");
        }

        // Store ciphertext first (outside the DB transaction), then commit rows.
        String storageRef = storage.storeEncrypted(manifest.getTransferId(), ciphertext);

        ImageTransfer row = new ImageTransfer();
        row.setTransferId(manifest.getTransferId());
        row.setSenderId(manifest.getSenderUserId());
        row.setRecipientId(manifest.getRecipientUserId());
        row.setOriginalFilename(manifest.getOriginalFilename());
        row.setContentType(manifest.getContentType());
        row.setPlaintextSize(manifest.getPlaintextSize());
        row.setCiphertextSize(manifest.getCiphertextSize());
        row.setPlaintextSha256(manifest.getPlaintextSha256());
        row.setAlgorithm(manifest.getAlgorithm());
        row.setKeySizeBits(manifest.getKeySizeBits());
        row.setNonce(manifest.getNonce());
        row.setTagBits(manifest.getTagBits());
        row.setStatus(TransferStatus.SENDING);
        row.setStorageRef(storageRef);
        row.setCreatedAtMs(manifest.getCreatedAtMs());

        long id = daos.transfers().insert(row);

        PublicKeyRecord recipientKey = daos.publicKeys().findLatestByUserId(manifest.getRecipientUserId());
        long recipientKeyId = recipientKey == null ? 0L : recipientKey.id;
        ProtectedKeyMaterial keyMaterial = new ProtectedKeyMaterial(
                manifest.getTransferId(), KeyProtector.WRAP_ALGORITHM_ID, wrappedKey,
                recipient.getUsername(), recipientKeyId,
                recipientKey == null ? 1 : recipientKey.keyVersion);
        daos.keys().insert(keyMaterial);

        boolean received = daos.transfers().markReceived(manifest.getTransferId(), storageRef,
                ciphertext.length);
        if (!received) {
            audit.failure(AuditEvent.TRANSFER_FAILED, authenticatedSender.getUsername(),
                    Long.valueOf(authenticatedSender.getId()), manifest.getTransferId(),
                    "Could not mark received", null);
            throw new IOException("Transfer state update failed");
        }

        // The sender-side encryption necessarily completed before submission.
        audit.success(AuditEvent.ENCRYPT_OK, authenticatedSender.getUsername(),
                Long.valueOf(authenticatedSender.getId()), manifest.getTransferId(),
                "AES-" + manifest.getKeySizeBits() + "-GCM ciphertext accepted ("
                        + manifest.getPlaintextSize() + " -> " + ciphertext.length + " bytes)", null);
        audit.success(AuditEvent.TRANSFER_RECV, authenticatedSender.getUsername(),
                Long.valueOf(authenticatedSender.getId()), manifest.getTransferId(),
                "Received " + ciphertext.length + " encrypted bytes for " + recipient.getUsername(), null);
        return id;
    }

    /** Incoming list for the addressed recipient (or any user for their own rows). */
    public List<ImageTransfer> listIncoming(User requester) throws SQLException {
        AuthorizationService.requireActive(requester);
        return daos.transfers().findByRecipientId(requester.getId());
    }

    /** Outgoing list for the sender (history). */
    public List<ImageTransfer> listOutgoing(User requester) throws SQLException {
        AuthorizationService.requireActive(requester);
        return daos.transfers().findBySenderId(requester.getId());
    }

    /** Full list for administrators (audit view). */
    public List<ImageTransfer> listAll(User admin, int limit) throws SQLException {
        AuthorizationService.requireAdmin(admin);
        return daos.transfers().findRecent(limit);
    }

    public ImageTransfer findTransfer(User requester, String transferId) throws SQLException {
        AuthorizationService.requireActive(requester);
        ImageTransfer transfer = daos.transfers().findByTransferId(transferId);
        if (transfer != null) {
            AuthorizationService.requireParticipantOrAdmin(requester, transfer);
        }
        return transfer;
    }

    /** Downloads the encrypted payload (recipient or admin only). */
    public byte[] downloadPayload(User requester, String transferId) throws SQLException, IOException {
        ImageTransfer transfer = daos.transfers().findByTransferId(transferId);
        if (transfer == null) {
            throw new IOException("Unknown transfer");
        }
        AuthorizationService.requireRecipientOrAdmin(requester, transfer);
        if (transfer.getStorageRef() == null) {
            throw new IOException("Transfer has no stored payload");
        }
        try {
            return storage.loadEncrypted(transfer.getStorageRef());
        } catch (IOException e) {
            throw new IOException("Stored payload could not be read (transfer may be incomplete)");
        }
    }

    /** Recipient rejects a transfer (status -> REJECTED). */
    public void rejectTransfer(User requester, String transferId, String reason, String sourceIp)
            throws SQLException {
        ImageTransfer transfer = daos.transfers().findByTransferId(transferId);
        if (transfer == null) {
            throw new IllegalArgumentException("Unknown transfer");
        }
        AuthorizationService.requireRecipientOrAdmin(requester, transfer);
        boolean ok = daos.transfers().updateStatus(transferId, TransferStatus.REJECTED,
                reason == null ? "Rejected by recipient" : Validation.sanitizeDetail(reason));
        if (!ok) {
            throw new IllegalStateException("Could not update transfer status");
        }
        audit.success(AuditEvent.TRANSFER_REJECTED, requester.getUsername(),
                Long.valueOf(requester.getId()), transferId, "Rejected", sourceIp);
    }

    /** Explicit status updates (VERIFIED/DECRYPTED/FAILED) with state checks. */
    public void markStatus(User requester, String transferId, TransferStatus next,
                           String errorDetail, String sourceIp) throws SQLException {
        ImageTransfer transfer = daos.transfers().findByTransferId(transferId);
        if (transfer == null) {
            throw new IllegalArgumentException("Unknown transfer");
        }
        AuthorizationService.requireParticipantOrAdmin(requester, transfer);
        boolean ok = daos.transfers().updateStatus(transferId, next,
                errorDetail == null ? null : Validation.sanitizeDetail(errorDetail));
        if (!ok) {
            throw new IllegalStateException("Could not update transfer status");
        }
        if (next == TransferStatus.DECRYPTED) {
            daos.transfers().markCompleted(transferId);
        }
        String eventType;
        if (next == TransferStatus.FAILED) {
            eventType = AuditEvent.TRANSFER_FAILED;
        } else if (next == TransferStatus.DECRYPTED) {
            eventType = AuditEvent.DECRYPT_OK;
        } else {
            eventType = AuditEvent.INTEGRITY_OK;
        }
        audit.success(eventType, requester.getUsername(), Long.valueOf(requester.getId()),
                transferId, "Status -> " + next, sourceIp);
    }
}
