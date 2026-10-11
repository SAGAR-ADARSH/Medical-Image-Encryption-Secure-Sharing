package com.medicalsecurity.crypto;

import com.medicalsecurity.util.SecureIds;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

/**
 * Recipient-specific key protection.
 *
 * <p>Design (documented key-wrapping scheme):
 * <ol>
 *   <li>Each image transfer gets a fresh AES-256 data-encryption key (DEK).</li>
 *   <li>The DEK is wrapped with the INTENDED RECIPIENT's RSA-2048 public key
 *       using RSA-OAEP (SHA-256, MGF1).</li>
 *   <li>Only the wrapped DEK is stored (database) or transmitted (socket).</li>
 *   <li>Only the matching RSA private key - kept in the recipient's PKCS#12
 *       keystore - can unwrap the DEK. A different recipient's key cannot.</li>
 * </ol>
 *
 * <p>Note on trust: in this architecture the key-management server stores the
 * wrapped keys and the public keys. Because recipient private keys never leave
 * the recipients' PKCS#12 keystores, the server cannot read image plaintext;
 * this is an actual property of the implemented design (wrapped-key storage,
 * local private keys), not a claim.
 */
public final class KeyProtector {

    /** Standard JCE transformation; the wrap format identifier recorded in the DB. */
    public static final String WRAP_ALGORITHM_ID = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int RSA_KEY_BITS = 2048;

    /** Generates an RSA-2048 recipient key pair (CSPRNG-backed). */
    public KeyPair generateRecipientKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(RSA_KEY_BITS, SecureIds.secureRandom());
            return kpg.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate RSA key pair", e);
        }
    }

    /** Wraps (encrypts) the AES DEK for the given recipient public key. */
    public byte[] wrapDataKey(PublicKey recipientPublicKey, SecretKey dataKey) throws GeneralSecurityException {
        if (recipientPublicKey == null || dataKey == null) {
            throw new IllegalArgumentException("recipient key and data key are required");
        }
        Cipher cipher = Cipher.getInstance(WRAP_ALGORITHM_ID);
        cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
        return cipher.doFinal(dataKey.getEncoded());
    }

    /**
     * Unwraps the DEK with the recipient private key. Any modification of the
     * wrapped bytes, or use of the wrong private key, fails the OAEP
     * integrity check and throws - no key material is released.
     */
    public SecretKey unwrapDataKey(PrivateKey recipientPrivateKey, byte[] wrappedKey)
            throws GeneralSecurityException {
        if (recipientPrivateKey == null || wrappedKey == null) {
            throw new IllegalArgumentException("private key and wrapped key are required");
        }
        Cipher cipher = Cipher.getInstance(WRAP_ALGORITHM_ID);
        cipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey);
        byte[] raw = cipher.doFinal(wrappedKey);
        try {
            return CryptoEngine.keyFromBytes(raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }
}
