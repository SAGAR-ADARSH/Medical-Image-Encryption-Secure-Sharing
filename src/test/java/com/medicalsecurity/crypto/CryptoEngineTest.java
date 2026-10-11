package com.medicalsecurity.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cryptographic engine tests (spec section 11):
 * round-trip fidelity, fresh parameters per encryption, tamper rejection,
 * wrong-key rejection and malformed-payload rejection.
 */
class CryptoEngineTest {

    private CryptoEngine crypto;

    @BeforeEach
    void setUp() {
        crypto = new CryptoEngine();
    }

    @Test
    @DisplayName("Encrypting and decrypting an image restores the exact original bytes")
    void roundTripRestoresExactBytes() throws Exception {
        final byte[] image = sampleImage(4096);
        final SecretKeyHolder key = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        final EncryptedPayload payload = crypto.encryptImageWithKey(
                new EncryptRequest(image, null), key.key);
        final byte[] recovered = crypto.decryptImage(new DecryptRequest(key.key, payload, null));
        assertArrayEquals(image, recovered, "recovered bytes must be identical");
    }

    @Test
    @DisplayName("Encrypting the same image twice produces different ciphertext")
    void freshParametersPerEncryption() throws Exception {
        final byte[] image = sampleImage(2048);
        final EncryptedPayload first = crypto.encryptImage(new EncryptRequest(image, null));
        final EncryptedPayload second = crypto.encryptImage(new EncryptRequest(image, null));
        assertFalse(java.util.Arrays.equals(first.getCiphertextWithTag(), second.getCiphertextWithTag()),
                "ciphertext must differ under fresh keys/nonces");
        assertFalse(java.util.Arrays.equals(first.getNonce(), second.getNonce()),
                "nonces must differ");
    }

    @Test
    @DisplayName("Tampered ciphertext fails authentication")
    void tamperedCiphertextIsRejected() throws Exception {
        final byte[] image = sampleImage(1024);
        final SecretKeyHolder key = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        final EncryptedPayload payload = crypto.encryptImageWithKey(new EncryptRequest(image, null), key.key);
        final byte[] cipher = payload.getCiphertextWithTag();
        cipher[cipher.length / 2] ^= 0x5A;
        final EncryptedPayload tampered = new EncryptedPayload(payload.getAlgorithm(), payload.getKeySizeBits(),
                payload.getNonce(), cipher, payload.getTagBits(), payload.getPlaintextSize());
        assertThrows(TamperedException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                crypto.decryptImage(new DecryptRequest(key.key, tampered, null));
            }
        });
    }

    @Test
    @DisplayName("Incorrect keys cannot successfully decrypt an image")
    void wrongKeyIsRejected() throws Exception {
        final byte[] image = sampleImage(1024);
        final SecretKeyHolder right = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        final SecretKeyHolder wrong = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        final EncryptedPayload payload = crypto.encryptImageWithKey(new EncryptRequest(image, null), right.key);
        assertThrows(TamperedException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                crypto.decryptImage(new DecryptRequest(wrong.key, payload, null));
            }
        });
    }

    @Test
    @DisplayName("Invalid or malformed payloads are rejected")
    void malformedPayloadsAreRejected() throws Exception {
        final SecretKeyHolder key = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        // Truncated ciphertext (shorter than the GCM tag).
        final EncryptedPayload tooShort = new EncryptedPayload("AES/GCM/NoPadding", 256,
                new byte[12], new byte[4], 128, 100);
        assertFalse(crypto.verifyEncryptedPayload(tooShort));
        // Wrong algorithm identifier.
        final EncryptedPayload wrongAlg = new EncryptedPayload("DES", 256,
                new byte[12], new byte[32], 128, 100);
        assertFalse(crypto.verifyEncryptedPayload(wrongAlg));
        // Wrong nonce length.
        final EncryptedPayload wrongNonce = new EncryptedPayload("AES/GCM/NoPadding", 256,
                new byte[8], new byte[32], 128, 100);
        assertFalse(crypto.verifyEncryptedPayload(wrongNonce));
        // Null payload.
        assertFalse(crypto.verifyEncryptedPayload(null));
        // Structural rejection happens before decryption.
        assertThrows(TamperedException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                crypto.decryptImage(new DecryptRequest(key.key, tooShort, null));
            }
        });
    }

    @Test
    @DisplayName("Nonce and key generation produce unique values")
    void nonceAndKeyUniqueness() throws Exception {
        final byte[] n1 = crypto.generateNonce();
        final byte[] n2 = crypto.generateNonce();
        assertEquals(12, n1.length);
        assertFalse(java.util.Arrays.equals(n1, n2), "nonces must be unique");
        SecretKeyHolder k1 = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        SecretKeyHolder k2 = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        assertFalse(java.util.Arrays.equals(k1.key.getEncoded(), k2.key.getEncoded()),
                "data keys must be unique per transfer");
        assertEquals(32, k1.key.getEncoded().length, "AES-256 key material");
    }

    @Test
    @DisplayName("Additional authenticated data is covered by the GCM tag")
    void aadMismatchIsRejected() throws Exception {
        final byte[] image = sampleImage(512);
        final SecretKeyHolder key = new SecretKeyHolder(crypto.generateDataEncryptionKey());
        final byte[] aad = "manifest-context-1".getBytes("UTF-8");
        final EncryptedPayload payload = crypto.encryptImageWithKey(new EncryptRequest(image, aad), key.key);
        // Decryption with the correct AAD succeeds.
        final byte[] ok = crypto.decryptImage(new DecryptRequest(key.key, payload, aad));
        assertArrayEquals(image, ok);
        // Decryption with modified AAD fails.
        final EncryptedPayload same = payload;
        assertThrows(TamperedException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                crypto.decryptImage(new DecryptRequest(key.key, same, "manifest-context-2".getBytes("UTF-8")));
            }
        });
    }

    private static byte[] sampleImage(int size) {
        final byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i * 31 + 7);
        }
        return data;
    }

    /** Small holder so anonymous classes can reference the key. */
    private static final class SecretKeyHolder {
        final javax.crypto.SecretKey key;

        SecretKeyHolder(javax.crypto.SecretKey key) {
            this.key = key;
        }
    }
}
