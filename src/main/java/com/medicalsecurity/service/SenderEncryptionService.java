package com.medicalsecurity.service;

import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.EncryptRequest;
import com.medicalsecurity.crypto.EncryptedPayload;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.model.TransferManifest;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationService;
import com.medicalsecurity.util.Hashing;
import com.medicalsecurity.util.IoUtils;
import com.medicalsecurity.util.SecureIds;
import com.medicalsecurity.util.Validation;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Sender-side encryption service (runs inside the doctor's application, so
 * plaintext image bytes never leave the sender's machine):
 * <ol>
 *   <li>validate the selected file (type + size),</li>
 *   <li>generate a fresh AES-256 DEK and a fresh random nonce,</li>
 *   <li>encrypt with AES-GCM, binding the manifest metadata as AAD,</li>
 *   <li>wrap the DEK with the INTENDED RECIPIENT's RSA public key.</li>
 * </ol>
 */
public final class SenderEncryptionService {

    private final CryptoEngine crypto;
    private final KeyProtector keyProtector;
    private final long maxFileBytes;

    public SenderEncryptionService(CryptoEngine crypto, KeyProtector keyProtector, long maxFileBytes) {
        this.crypto = crypto;
        this.keyProtector = keyProtector;
        this.maxFileBytes = maxFileBytes;
    }

    /** Reads an image file with validation and a hard size cap. */
    public byte[] readImageFile(Path imageFile) throws IOException {
        if (imageFile == null) {
            throw new IllegalArgumentException("No file selected");
        }
        Validation.requireSupportedImageFilename(imageFile.getFileName().toString());
        return IoUtils.readFileBounded(imageFile, maxFileBytes);
    }

    /**
     * Encrypts the image and protects the DEK for the recipient.
     *
     * @param sender          authenticated sender (session identity)
     * @param recipient       intended recipient (from the server's recipient list)
     * @param originalFilename local file name (validated/sanitised)
     * @param imageBytes      original image bytes (bounded by maxFileBytes)
     * @param recipientPublic recipient's RSA public key (from the key registry)
     */
    public PreparedTransfer prepareOutgoing(User sender, User recipient, String originalFilename,
                                            byte[] imageBytes, PublicKey recipientPublic)
            throws GeneralSecurityException, IOException {
        AuthorizationService.requireCanSend(sender);
        Validation.requireSupportedImageFilename(originalFilename);
        String safeName = Validation.sanitizeFilename(originalFilename);
        if (imageBytes == null || imageBytes.length == 0) {
            throw new IllegalArgumentException("Image is empty");
        }
        if (imageBytes.length > maxFileBytes) {
            throw new IllegalArgumentException("Image exceeds the maximum allowed size ("
                    + maxFileBytes + " bytes)");
        }
        if (recipient == null) {
            throw new IllegalArgumentException("Recipient is required");
        }
        if (recipientPublic == null) {
            throw new IllegalArgumentException("Recipient public key is required");
        }

        // Fresh key material for this transfer only.
        SecretKey dek = crypto.generateDataEncryptionKey();
        String transferId = SecureIds.newTransferId();
        String plaintextSha256 = Hashing.sha256Hex(imageBytes);

        TransferManifest manifest = new TransferManifest();
        manifest.setTransferId(transferId);
        manifest.setSenderUserId(sender.getId());
        manifest.setRecipientUserId(recipient.getId());
        manifest.setSenderUsername(sender.getUsername());
        manifest.setRecipientUsername(recipient.getUsername());
        manifest.setOriginalFilename(safeName);
        manifest.setContentType(guessContentType(safeName));
        manifest.setPlaintextSize(imageBytes.length);
        // GCM ciphertext length = plaintext length + appended authentication tag.
        manifest.setCiphertextSize(imageBytes.length + CryptoEngine.GCM_TAG_BITS / 8);
        manifest.setPlaintextSha256(plaintextSha256);
        manifest.setAlgorithm(CryptoEngine.AES_GCM_ALGORITHM);
        manifest.setKeySizeBits(CryptoEngine.AES_KEY_BITS);
        manifest.setNonce(crypto.generateNonce());
        manifest.setTagBits(CryptoEngine.GCM_TAG_BITS);
        manifest.setCreatedAtMs(System.currentTimeMillis());
        manifest.validate();

        // Encrypt with the manifest context as AAD (metadata is authenticated too).
        EncryptedPayload payload = crypto.encryptImageWithKey(
                new EncryptRequest(imageBytes, manifest.toAuthenticatedContext()), dek);
        manifest.setNonce(payload.getNonce());
        if (payload.getCiphertextWithTag().length != manifest.getCiphertextSize()) {
            throw new GeneralSecurityException("Unexpected ciphertext size");
        }
        manifest.validate();

        byte[] wrappedKey = keyProtector.wrapDataKey(recipientPublic, dek);
        return new PreparedTransfer(manifest, wrappedKey, payload.getCiphertextWithTag(), imageBytes);
    }

    static String guessContentType(String filename) {
        String lower = filename.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        if (lower.endsWith(".bmp")) {
            return "image/bmp";
        }
        if (lower.endsWith(".gif")) {
            return "image/gif";
        }
        return "application/octet-stream";
    }
}
