package com.medicalsecurity.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * One-way hash helpers (SHA-256). Used to fingerprint image plaintext so the
 * receiver can prove byte-for-byte equality after decryption. Not a password
 * hash - see com.medicalsecurity.crypto.PasswordHasher for those.
 */
public final class Hashing {

    public static final String SHA256_ALGORITHM = "SHA-256";

    private Hashing() {
    }

    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA256_ALGORITHM);
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable in this JVM", e);
        }
    }

    public static String sha256Hex(byte[] data) {
        return Hex.encode(sha256(data));
    }

    /**
     * Constant-time comparison of two digests (avoids timing side channels
     * when comparing authentication material).
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a, b);
    }
}
