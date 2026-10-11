package com.medicalsecurity.service;

import java.util.Arrays;

/**
 * Result of an authenticated decryption: the recovered plaintext plus the
 * outcome of the integrity checks. Only produced when AES-GCM tag
 * verification AND the SHA-256 comparison both succeed.
 */
public final class DecryptionResult {

    private final byte[] recoveredPlaintext;
    private final String plaintextSha256;
    private final boolean gcmAuthenticated;
    private final boolean hashMatches;

    DecryptionResult(byte[] recoveredPlaintext, String plaintextSha256,
                     boolean gcmAuthenticated, boolean hashMatches) {
        this.recoveredPlaintext = java.util.Arrays.copyOf(recoveredPlaintext, recoveredPlaintext.length);
        this.plaintextSha256 = plaintextSha256;
        this.gcmAuthenticated = gcmAuthenticated;
        this.hashMatches = hashMatches;
    }

    public byte[] getRecoveredPlaintext() {
        return java.util.Arrays.copyOf(recoveredPlaintext, recoveredPlaintext.length);
    }

    public String getPlaintextSha256() {
        return plaintextSha256;
    }

    public boolean isGcmAuthenticated() {
        return gcmAuthenticated;
    }

    public boolean isHashMatches() {
        return hashMatches;
    }

    public boolean isVerified() {
        return gcmAuthenticated && hashMatches;
    }

    /** Constant-time equality helper for byte-for-byte comparisons in tests/demo. */
    public boolean matches(byte[] original) {
        return original != null && Arrays.equals(recoveredPlaintext, original);
    }
}
