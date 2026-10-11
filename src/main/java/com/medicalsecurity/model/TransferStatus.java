package com.medicalsecurity.model;

import java.util.Locale;

/**
 * Transfer lifecycle. The transitions below are enforced by the backend on
 * every status update (replay/interleaving protection: a transfer can never
 * jump backwards or skip verification).
 */
public enum TransferStatus {
    PENDING,
    ENCRYPTING,
    SENDING,
    RECEIVED,
    VERIFIED,
    DECRYPTED,
    FAILED,
    REJECTED;

    public static TransferStatus fromString(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Status must not be null");
        }
        return valueOf(value.trim().toUpperCase(Locale.ROOT));
    }

    /** Explicit state machine: which transitions are legal. */
    public boolean canTransitionTo(TransferStatus next) {
        if (next == null) {
            return false;
        }
        switch (this) {
            case PENDING:
                return next == ENCRYPTING || next == FAILED || next == REJECTED;
            case ENCRYPTING:
                return next == SENDING || next == FAILED;
            case SENDING:
                return next == RECEIVED || next == FAILED;
            case RECEIVED:
                return next == VERIFIED || next == REJECTED || next == FAILED;
            case VERIFIED:
                return next == DECRYPTED || next == FAILED;
            case DECRYPTED:
                return next == FAILED;
            case FAILED:
            case REJECTED:
                return false;
            default:
                return false;
        }
    }

    public boolean isTerminal() {
        return this == DECRYPTED || this == FAILED || this == REJECTED;
    }
}
