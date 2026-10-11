package com.medicalsecurity.util;

import java.security.SecureRandom;
import java.util.UUID;

/**
 * Cryptographically secure identifier generation. Transfer IDs and session
 * tokens are always produced with {@link SecureRandom} - never
 * {@code java.util.Random} or timestamp-based schemes.
 */
public final class SecureIds {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] TOKEN_ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private SecureIds() {
    }

    /** Unique transfer identifier (UUID v4, replay-resistant primary key of a transfer). */
    public static String newTransferId() {
        return UUID.randomUUID().toString();
    }

    /** Opaque session token (28 random chars + padding-free alphabet, 168 bits). */
    public static String newSessionToken() {
        return randomToken(28);
    }

    /** Random token of the given length from a 62-symbol alphabet. */
    public static String randomToken(int length) {
        if (length <= 0) {
            throw new IllegalArgumentException("length must be positive");
        }
        char[] out = new char[length];
        synchronized (RANDOM) {
            for (int i = 0; i < length; i++) {
                out[i] = TOKEN_ALPHABET[RANDOM.nextInt(TOKEN_ALPHABET.length)];
            }
        }
        return new String(out);
    }

    /** Random bytes (e.g. GCM nonces, password salts). */
    public static byte[] randomBytes(int count) {
        byte[] out = new byte[count];
        synchronized (RANDOM) {
            RANDOM.nextBytes(out);
        }
        return out;
    }

    /** Shared secure random for key generation (AES/RSA key generators). */
    public static SecureRandom secureRandom() {
        return RANDOM;
    }
}
