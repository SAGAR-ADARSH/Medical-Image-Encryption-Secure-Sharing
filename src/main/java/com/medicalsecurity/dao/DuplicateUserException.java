package com.medicalsecurity.dao;

/** Raised when a unique constraint on user accounts would be violated. */
public class DuplicateUserException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public DuplicateUserException(String message) {
        super(message);
    }

    public DuplicateUserException(String message, Throwable cause) {
        super(message, cause);
    }
}
