package com.medicalsecurity.model;

import java.util.Arrays;

/**
 * The per-transfer AES data-encryption key in its PROTECTED form: wrapped with
 * the intended recipient's RSA public key (RSA-OAEP SHA-256). Only this
 * wrapped form is ever stored in the database or sent over the network; the
 * plaintext DEK exists only transiently inside the sender/receiver processes.
 */
public final class ProtectedKeyMaterial {

    private final String transferId;
    private final String wrapAlgorithm;
    private final byte[] wrappedKey;
    private final String recipientUsername;
    private final long recipientKeyId;
    private final int keyVersion;

    public ProtectedKeyMaterial(String transferId, String wrapAlgorithm, byte[] wrappedKey,
                                String recipientUsername, long recipientKeyId, int keyVersion) {
        this.transferId = transferId;
        this.wrapAlgorithm = wrapAlgorithm;
        this.wrappedKey = wrappedKey == null ? null : Arrays.copyOf(wrappedKey, wrappedKey.length);
        this.recipientUsername = recipientUsername;
        this.recipientKeyId = recipientKeyId;
        this.keyVersion = keyVersion;
    }

    public String getTransferId() {
        return transferId;
    }

    public String getWrapAlgorithm() {
        return wrapAlgorithm;
    }

    public byte[] getWrappedKey() {
        return wrappedKey == null ? null : Arrays.copyOf(wrappedKey, wrappedKey.length);
    }

    public String getRecipientUsername() {
        return recipientUsername;
    }

    public long getRecipientKeyId() {
        return recipientKeyId;
    }

    public int getKeyVersion() {
        return keyVersion;
    }
}
