package com.medicalsecurity.service;

import com.medicalsecurity.dao.DaoFactory;
import com.medicalsecurity.dao.PublicKeyRecord;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationService;

import java.security.PublicKey;
import java.sql.SQLException;

/**
 * Key-management component (server side of the documented design):
 * <ul>
 *   <li>registers user PUBLIC keys (private keys stay in PKCS#12 keystores),</li>
 *   <li>serves public keys so senders can wrap per-transfer DEKs,</li>
 *   <li>stores and releases PROTECTED (RSA-OAEP wrapped) key material,</li>
 *   <li>enforces recipient-only key release with audit events.</li>
 * </ul>
 * The service never handles plaintext key material: wrapped DEKs go in and
 * out unchanged; unwrapping happens exclusively on the recipient's machine
 * with the recipient's private key.
 */
public final class KeyManagementService {

    private final DaoFactory daos;
    private final AuditService audit;

    public KeyManagementService(DaoFactory daos, AuditService audit) {
        this.daos = daos;
        this.audit = audit;
    }

    /** Registers (or replaces) a user's public key metadata. */
    public long registerUserPublicKey(long userId, String username, String algorithm,
                                      int keySizeBits, byte[] publicKeyDer, int keyVersion,
                                      String keystoreRef) throws SQLException {
        return daos.publicKeys().insert(userId, algorithm, keySizeBits, publicKeyDer,
                keyVersion, keystoreRef);
    }

    /**
     * Public key lookup. Any ACTIVE authenticated user may read public keys -
     * they are public - but the query is still audited and validated.
     */
    public PublicKeyRecord getPublicKey(User requester, String username) {
        AuthorizationService.requireActive(requester);
        if (username == null || username.trim().isEmpty()) {
            throw new IllegalArgumentException("Username is required");
        }
        try {
            PublicKeyRecord record = daos.publicKeys().findLatestByUsername(username.trim());
            if (record == null) {
                throw new IllegalArgumentException("No public key registered for " + username);
            }
            return record;
        } catch (SQLException e) {
            throw new IllegalStateException("Public key lookup failed");
        }
    }

    /**
     * Releases the WRAPPED DEK of one transfer - only to the addressed
     * recipient (not even the sender, not other specialists).
     */
    public ProtectedKeyMaterial releaseWrappedKey(User requester, String transferId, String sourceIp) {
        ImageTransfer transfer;
        try {
            transfer = daos.transfers().findByTransferId(transferId);
        } catch (SQLException e) {
            throw new IllegalStateException("Transfer lookup failed");
        }
        if (transfer == null) {
            throw new IllegalArgumentException("Unknown transfer");
        }
        try {
            AuthorizationService.requireKeyReleasePermission(requester, transfer);
        } catch (RuntimeException e) {
            audit.denied(AuditEvent.KEY_RELEASE_DENIED, requester.getUsername(),
                    Long.valueOf(requester.getId()), transferId, "Not the addressed recipient", sourceIp);
            throw e;
        }
        ProtectedKeyMaterial material;
        try {
            material = daos.keys().findByTransferId(transferId);
        } catch (SQLException e) {
            throw new IllegalStateException("Key lookup failed");
        }
        if (material == null) {
            throw new IllegalArgumentException("No protected key material for this transfer");
        }
        audit.success(AuditEvent.KEY_RELEASE, requester.getUsername(),
                Long.valueOf(requester.getId()), transferId,
                "Wrapped DEK released (" + material.getWrapAlgorithm() + ")", sourceIp);
        return material;
    }
}
