package com.medicalsecurity.service;

import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.DecryptRequest;
import com.medicalsecurity.crypto.EncryptedPayload;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.crypto.TamperedException;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferManifest;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationService;
import com.medicalsecurity.util.Hashing;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

/**
 * Recipient-side decryption service (runs inside the specialist's
 * application). Unwraps the DEK with the recipient's LOCAL private key and
 * only returns plaintext after AES-GCM tag verification and SHA-256
 * comparison both succeed. The key-management server is not involved in the
 * unwrap step and therefore cannot decrypt payloads itself.
 */
public final class ReceiverDecryptionService {

    private final CryptoEngine crypto;
    private final KeyProtector keyProtector;

    public ReceiverDecryptionService(CryptoEngine crypto, KeyProtector keyProtector) {
        this.crypto = crypto;
        this.keyProtector = keyProtector;
    }

    /**
     * Authenticates and decrypts a received payload.
     *
     * @param recipient           the logged-in recipient (authorization is enforced again)
     * @param transfer            transfer metadata as recorded by the server
     * @param wrappedKey          RSA-OAEP wrapped DEK from the key service
     * @param ciphertext          encrypted payload downloaded from the transfer service
     * @param recipientPrivateKey the recipient's private key from the local PKCS#12 keystore
     * @throws TamperedException on any authentication failure (no plaintext is released)
     */
    public DecryptionResult decryptIncoming(User recipient, ImageTransfer transfer,
                                            byte[] wrappedKey, byte[] ciphertext,
                                            PrivateKey recipientPrivateKey)
            throws GeneralSecurityException, TamperedException {
        AuthorizationService.requireDecryptPermission(recipient, transfer);
        if (ciphertext == null || ciphertext.length != transfer.getCiphertextSize()) {
            throw new TamperedException("Ciphertext size mismatch - payload is corrupt or truncated");
        }
        if (wrappedKey == null || wrappedKey.length == 0) {
            throw new TamperedException("Missing protected key material");
        }

        SecretKey dek;
        try {
            dek = keyProtector.unwrapDataKey(recipientPrivateKey, wrappedKey);
        } catch (GeneralSecurityException e) {
            throw new TamperedException("Could not unwrap the data key for this recipient", e);
        }

        EncryptedPayload payload = new EncryptedPayload(
                transfer.getAlgorithm(), transfer.getKeySizeBits(), transfer.getNonce(),
                ciphertext, transfer.getTagBits(), transfer.getPlaintextSize());
        if (!crypto.verifyEncryptedPayload(payload)) {
            throw new TamperedException("Encrypted payload is malformed");
        }

        byte[] aad = TransferManifest.authenticatedContext(
                transfer.getTransferId(), transfer.getSenderId(), transfer.getRecipientId(),
                transfer.getOriginalFilename(), transfer.getPlaintextSize(), transfer.getCiphertextSize(),
                transfer.getPlaintextSha256(), transfer.getAlgorithm(), transfer.getKeySizeBits(),
                transfer.getTagBits());

        byte[] plaintext = crypto.decryptImage(new DecryptRequest(dek, payload, aad));

        String recoveredHash = Hashing.sha256Hex(plaintext);
        boolean hashMatches = recoveredHash.equalsIgnoreCase(transfer.getPlaintextSha256());
        if (!hashMatches) {
            throw new TamperedException("Recovered image does not match the recorded SHA-256 digest");
        }
        return new DecryptionResult(plaintext, recoveredHash, true, true);
    }
}
