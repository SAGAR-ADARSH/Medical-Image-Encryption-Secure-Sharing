package com.medicalsecurity.crypto;

import java.util.Arrays;

/**
 * Result of an encryption operation: ciphertext plus every parameter needed
 * to decrypt it later (algorithm identifier, nonce, tag length). The GCM
 * authentication tag is appended to the ciphertext by the JCE provider.
 */
public final class EncryptedPayload {

    private final String algorithm;
    private final int keySizeBits;
    private final byte[] nonce;
    private final byte[] ciphertextWithTag;
    private final int tagBits;
    private final long plaintextSize;

    public EncryptedPayload(String algorithm, int keySizeBits, byte[] nonce,
                            byte[] ciphertextWithTag, int tagBits, long plaintextSize) {
        this.algorithm = algorithm;
        this.keySizeBits = keySizeBits;
        this.nonce = nonce == null ? null : Arrays.copyOf(nonce, nonce.length);
        this.ciphertextWithTag = ciphertextWithTag == null ? null : Arrays.copyOf(ciphertextWithTag, ciphertextWithTag.length);
        this.tagBits = tagBits;
        this.plaintextSize = plaintextSize;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public int getKeySizeBits() {
        return keySizeBits;
    }

    public byte[] getNonce() {
        return nonce == null ? null : Arrays.copyOf(nonce, nonce.length);
    }

    /** Ciphertext with the GCM tag appended (JCE standard layout). */
    public byte[] getCiphertextWithTag() {
        return ciphertextWithTag == null ? null : Arrays.copyOf(ciphertextWithTag, ciphertextWithTag.length);
    }

    public int getTagBits() {
        return tagBits;
    }

    public long getPlaintextSize() {
        return plaintextSize;
    }

    public int getTagBytes() {
        return tagBits / 8;
    }
}
