package com.medicalsecurity.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Key wrapping tests (spec section 11): a data key must unwrap only with the
 * matching private key; wrapped keys must not contain the raw key.
 */
class KeyProtectorTest {

    @Test
    @DisplayName("A wrapped data key unwraps only with the matching private key")
    void wrapAndUnwrapRoundTrip() throws Exception {
        final KeyProtector protector = new KeyProtector();
        final KeyPair recipient = protector.generateRecipientKeyPair();
        SecretKey dataKey = new CryptoEngine().generateDataEncryptionKey();
        final byte[] wrapped = protector.wrapDataKey(recipient.getPublic(), dataKey);
        SecretKey unwrapped = protector.unwrapDataKey(recipient.getPrivate(), wrapped);
        assertArrayEquals(dataKey.getEncoded(), unwrapped.getEncoded(),
                "unwrapped key must equal the original");

        // Wrong private key cannot unwrap.
        final KeyPair attacker = protector.generateRecipientKeyPair();
        assertThrows(Exception.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                protector.unwrapDataKey(attacker.getPrivate(), wrapped);
            }
        });
    }

    @Test
    @DisplayName("Wrapped keys do not expose raw key material")
    void wrappedKeyDoesNotContainRawKey() throws Exception {
        KeyProtector protector = new KeyProtector();
        KeyPair recipient = protector.generateRecipientKeyPair();
        SecretKey dataKey = new CryptoEngine().generateDataEncryptionKey();
        byte[] wrapped = protector.wrapDataKey(recipient.getPublic(), dataKey);
        byte[] raw = dataKey.getEncoded();
        assertFalse(containsSubArray(wrapped, raw), "wrapped output must not contain the raw DEK");
        assertTrue(wrapped.length >= 256, "RSA-2048 wrap output is at least 256 bytes");
    }

    @Test
    @DisplayName("Key generation produces RSA-2048 pairs")
    void keyPairParameters() throws Exception {
        KeyProtector protector = new KeyProtector();
        KeyPair pair = protector.generateRecipientKeyPair();
        PublicKey pub = pair.getPublic();
        PrivateKey priv = pair.getPrivate();
        assertTrue(pub.getAlgorithm().equals("RSA"), "public key algorithm");
        assertTrue(priv.getAlgorithm().equals("RSA"), "private key algorithm");
        assertTrue(pub.getEncoded().length > 250, "SubjectPublicKeyInfo present");
        assertNotNull(priv.getEncoded());
    }

    private static boolean containsSubArray(byte[] haystack, byte[] needle) {
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return true;
            }
        }
        return false;
    }
}
