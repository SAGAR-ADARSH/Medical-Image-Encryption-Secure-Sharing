package com.medicalsecurity.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Password hashing tests (spec section 11): salted iterative hashing, plain
 * text never stored, verification semantics.
 */
class PasswordHasherTest {

    @Test
    @DisplayName("Hashed passwords never contain the plaintext and use unique salts")
    void hashesAreSaltedAndOpaque() throws Exception {
        final PasswordHasher hasher = new PasswordHasher();
        final String h1 = hasher.hash("correct horse battery".toCharArray());
        final String h2 = hasher.hash("correct horse battery".toCharArray());
        assertFalse(h1.contains("correct horse battery"), "hash must not contain the password");
        assertNotEquals(h1, h2, "two hashes of the same password must differ (unique salt)");
        assertTrue(h1.startsWith("$pbkdf2-sha512$") || h1.startsWith("$argon2id$"),
                "hash format is a recognised modular scheme");
    }

    @Test
    @DisplayName("Correct passwords verify, incorrect ones do not")
    void verificationSemantics() throws Exception {
        final PasswordHasher hasher = new PasswordHasher();
        final String hash = hasher.hash("S3cure-Passw0rd!".toCharArray());
        assertTrue(hasher.verify("S3cure-Passw0rd!".toCharArray(), hash), "correct password verifies");
        assertFalse(hasher.verify("S3cure-Passw0rd".toCharArray(), hash), "wrong password fails");
        assertFalse(hasher.verify(new char[0], hash), "empty password fails");
        assertFalse(hasher.verify("S3cure-Passw0rd!".toCharArray(), "not-a-valid-hash"), "malformed hash fails");
    }

    @Test
    @DisplayName("Plaintext password validation rejects empty values")
    void emptyPasswordRejected() throws Exception {
        final PasswordHasher hasher = new PasswordHasher();
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                hasher.hash(new char[0]);
            }
        });
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                hasher.hash(null);
            }
        });
    }
}
