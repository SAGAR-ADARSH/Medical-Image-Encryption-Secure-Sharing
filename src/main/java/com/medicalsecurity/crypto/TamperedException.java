package com.medicalsecurity.crypto;

/**
 * Thrown whenever AES-GCM authentication fails: modified ciphertext, wrong
 * key, wrong nonce, or modified additional authenticated data. No plaintext
 * (not even partially decrypted data) is ever released when this is thrown.
 */
public class TamperedException extends Exception {

    private static final long serialVersionUID = 1L;

    public TamperedException(String message) {
        super(message);
    }

    public TamperedException(String message, Throwable cause) {
        super(message, cause);
    }
}
