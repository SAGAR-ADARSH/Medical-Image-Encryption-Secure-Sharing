package com.medicalsecurity.security;

/** Thrown when an authenticated user attempts an action outside their role. */
public class AuthorizationException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public AuthorizationException(String message) {
        super(message);
    }
}
