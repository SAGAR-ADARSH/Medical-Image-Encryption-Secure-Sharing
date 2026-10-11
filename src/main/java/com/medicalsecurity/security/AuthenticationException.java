package com.medicalsecurity.security;

/** Thrown when credential verification fails (bad password, unknown user). */
public class AuthenticationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AuthenticationException(String message) {
        super(message);
    }
}
