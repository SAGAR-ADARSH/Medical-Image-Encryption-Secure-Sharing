package com.medicalsecurity.crypto;

import com.medicalsecurity.util.SecureIds;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Authenticated encryption engine for medical images.
 *
 * <p>Algorithm: AES-GCM (JCE {@code AES/GCM/NoPadding}) with
 * {@value #AES_KEY_BITS}-bit keys, {@value #GCM_NONCE_BYTES}-byte nonces and
 * {@value #GCM_TAG_BITS}-bit authentication tags. Every transfer uses a fresh
 * cryptographically random key and a fresh random nonce, so encrypting the
 * same image twice never produces identical ciphertext.
 *
 * <p>This engine uses the standard Java Cryptography Extensions (a compatible
 * Java cryptography API). When the Bouncy Castle provider is present on the
 * classpath it is registered as an additional JCE provider; the algorithm
 * behaviour is identical either way. No custom cryptography is implemented.
 *
 * <p>Mandated entry points:
 * <ul>
 *   <li>{@link #encryptImage(EncryptRequest)}</li>
 *   <li>{@link #decryptImage(DecryptRequest)}</li>
 *   <li>{@link #generateDataEncryptionKey()}</li>
 *   <li>{@link #generateNonce()}</li>
 *   <li>{@link #verifyEncryptedPayload(EncryptedPayload)}</li>
 * </ul>
 */
public final class CryptoEngine {

    public static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    public static final int AES_KEY_BITS = 256;
    public static final int GCM_NONCE_BYTES = 12;
    public static final int GCM_TAG_BITS = 128;

    private final SecureRandom random;

    static {
        registerBouncyCastleIfPresent();
    }

    public CryptoEngine() {
        this.random = SecureIds.secureRandom();
    }

    /**
     * Registers the Bouncy Castle provider when it is on the classpath.
     * Uses reflection so the application also runs with pure JCE.
     */
    private static void registerBouncyCastleIfPresent() {
        try {
            Class<?> providerClass = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            java.security.Provider provider = (java.security.Provider) providerClass.getDeclaredConstructor().newInstance();
            if (java.security.Security.getProvider(provider.getName()) == null) {
                java.security.Security.addProvider(provider);
            }
        } catch (Throwable ignored) {
            // Bouncy Castle not present - the standard JCE provider is used.
        }
    }

    /** Algorithm identifier stored alongside every payload. */
    public static String algorithmId() {
        return AES_GCM_ALGORITHM + "/" + AES_KEY_BITS + "/GCM/" + GCM_TAG_BITS;
    }

    /**
     * Generates a fresh AES-256 data-encryption key (DEK) with the platform
     * CSPRNG. A new key is generated for EVERY image transfer.
     */
    public SecretKey generateDataEncryptionKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(AES_KEY_BITS, random);
            return kg.generateKey();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to generate AES key", e);
        }
    }

    /** Generates a unique random 12-byte GCM nonce. */
    public byte[] generateNonce() {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        random.nextBytes(nonce);
        return nonce;
    }

    /**
     * Encrypts the image bytes without modifying them (the plaintext is only
     * read). Produces a payload carrying the nonce, algorithm metadata and the
     * ciphertext with the appended GCM authentication tag.
     */
    public EncryptedPayload encryptImage(EncryptRequest request) throws GeneralSecurityException {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        SecretKey key = generateDataEncryptionKey();
        return encryptImageWithKey(request, key);
    }

    /**
     * Encrypts with a caller-supplied DEK (used by the transfer flow, where
     * the freshly generated DEK must also be wrapped for the recipient).
     */
    public EncryptedPayload encryptImageWithKey(EncryptRequest request, SecretKey key)
            throws GeneralSecurityException {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }
        byte[] nonce = generateNonce();
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] aad = request.getAdditionalAuthenticatedData();
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] plaintext = request.getPlaintext();
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new EncryptedPayload(AES_GCM_ALGORITHM, AES_KEY_BITS, nonce, ciphertext, GCM_TAG_BITS, plaintext.length);
    }

    /**
     * Authenticates and decrypts a payload.
     *
     * <p>The GCM authentication tag is verified by {@code doFinal}; if the
     * ciphertext, nonce, key or AAD is wrong, a {@link TamperedException} is
     * thrown and NO plaintext (partial or complete) is released.
     */
    public byte[] decryptImage(DecryptRequest request) throws GeneralSecurityException, TamperedException {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        EncryptedPayload payload = request.getPayload();
        if (!verifyEncryptedPayload(payload)) {
            throw new TamperedException("Encrypted payload is malformed and was rejected before decryption");
        }
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(payload.getTagBits(), payload.getNonce());
            cipher.init(Cipher.DECRYPT_MODE, request.getDataKey(), spec);
            byte[] aad = request.getAdditionalAuthenticatedData();
            if (aad != null && aad.length > 0) {
                cipher.updateAAD(aad);
            }
            byte[] plaintext = cipher.doFinal(payload.getCiphertextWithTag());
            if (plaintext.length != payload.getPlaintextSize()) {
                throw new TamperedException("Decrypted size does not match the manifest");
            }
            return plaintext;
        } catch (GeneralSecurityException e) {
            // AEADBadTagException / BadPaddingException / InvalidKeyException etc.
            throw new TamperedException(
                    "Authentication failed: the ciphertext was modified, corrupted or the key is incorrect", e);
        }
    }

    /**
     * Structural verification of an encrypted payload: algorithm identifier,
     * nonce length, tag length and minimum ciphertext size. Rejects malformed
     * or truncated inputs before any cryptographic processing.
     */
    public boolean verifyEncryptedPayload(EncryptedPayload payload) {
        if (payload == null) {
            return false;
        }
        if (payload.getAlgorithm() == null || !AES_GCM_ALGORITHM.equals(payload.getAlgorithm())) {
            return false;
        }
        if (payload.getKeySizeBits() != AES_KEY_BITS) {
            return false;
        }
        byte[] nonce = payload.getNonce();
        if (nonce == null || nonce.length != GCM_NONCE_BYTES) {
            return false;
        }
        if (payload.getTagBits() != GCM_TAG_BITS) {
            return false;
        }
        byte[] ciphertext = payload.getCiphertextWithTag();
        if (ciphertext == null || ciphertext.length < payload.getTagBytes()) {
            return false;
        }
        return payload.getPlaintextSize() >= 0;
    }

    /**
     * Reconstructs a secret key from raw bytes (used after unwrapping the
     * per-transfer DEK on the recipient side). The raw bytes are the sensitive
     * material - callers must not log or persist them.
     */
    public static SecretKey keyFromBytes(byte[] rawKey) {
        if (rawKey == null || (rawKey.length != 16 && rawKey.length != 24 && rawKey.length != 32)) {
            throw new IllegalArgumentException("Invalid AES key length");
        }
        return new SecretKeySpec(rawKey, "AES");
    }
}
