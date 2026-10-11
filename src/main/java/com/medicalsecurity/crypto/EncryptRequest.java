package com.medicalsecurity.crypto;

/**
 * Typed request for {@link CryptoEngine#encryptImage(EncryptRequest)}.
 */
public final class EncryptRequest {

    private final byte[] plaintext;
    private final byte[] additionalAuthenticatedData;

    /**
     * @param plaintext                    the original image bytes
     * @param additionalAuthenticatedData  optional AAD (e.g. the transfer
     *                                     manifest context) that is bound to
     *                                     the ciphertext; may be {@code null}
     */
    public EncryptRequest(byte[] plaintext, byte[] additionalAuthenticatedData) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }
        this.plaintext = java.util.Arrays.copyOf(plaintext, plaintext.length);
        this.additionalAuthenticatedData =
                additionalAuthenticatedData == null ? null : java.util.Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
    }

    public byte[] getPlaintext() {
        return java.util.Arrays.copyOf(plaintext, plaintext.length);
    }

    public byte[] getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData == null ? null : java.util.Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
    }
}
