package com.medicalsecurity.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Transfer state-machine tests (spec section 11): permitted and forbidden
 * status transitions.
 */
class TransferStatusTest {

    @Test
    @DisplayName("Normal lifecycle transitions are permitted")
    void legalTransitions() {
        assertTrue(TransferStatus.PENDING.canTransitionTo(TransferStatus.ENCRYPTING));
        assertTrue(TransferStatus.ENCRYPTING.canTransitionTo(TransferStatus.SENDING));
        assertTrue(TransferStatus.SENDING.canTransitionTo(TransferStatus.RECEIVED));
        assertTrue(TransferStatus.RECEIVED.canTransitionTo(TransferStatus.VERIFIED));
        assertTrue(TransferStatus.VERIFIED.canTransitionTo(TransferStatus.DECRYPTED));
        assertTrue(TransferStatus.SENDING.canTransitionTo(TransferStatus.FAILED));
        assertTrue(TransferStatus.RECEIVED.canTransitionTo(TransferStatus.REJECTED));
    }

    @Test
    @DisplayName("Skipping steps or going backwards is forbidden")
    void illegalTransitions() {
        assertFalse(TransferStatus.PENDING.canTransitionTo(TransferStatus.DECRYPTED),
                "cannot jump from PENDING to DECRYPTED");
        assertFalse(TransferStatus.RECEIVED.canTransitionTo(TransferStatus.SENDING),
                "cannot move backwards");
        assertFalse(TransferStatus.VERIFIED.canTransitionTo(TransferStatus.RECEIVED),
                "cannot jump back before verification");
        assertFalse(TransferStatus.REJECTED.canTransitionTo(TransferStatus.VERIFIED),
                "rejected transfers cannot be verified");
        assertFalse(TransferStatus.FAILED.canTransitionTo(TransferStatus.DECRYPTED));
        assertFalse(TransferStatus.FAILED.canTransitionTo(TransferStatus.RECEIVED));
    }

    @Test
    @DisplayName("Terminal states are classified correctly")
    void terminalStates() {
        assertTrue(TransferStatus.DECRYPTED.isTerminal());
        assertTrue(TransferStatus.REJECTED.isTerminal());
        assertTrue(TransferStatus.FAILED.isTerminal());
        assertFalse(TransferStatus.PENDING.isTerminal());
        assertFalse(TransferStatus.RECEIVED.isTerminal());
        assertFalse(TransferStatus.VERIFIED.isTerminal());
    }

    @Test
    @DisplayName("Status values round-trip through their string form")
    void statusStringRoundTrip() {
        assertTrue(TransferStatus.fromString("RECEIVED") == TransferStatus.RECEIVED);
        assertTrue(TransferStatus.fromString("DECRYPTED") == TransferStatus.DECRYPTED);
        assertThrows(IllegalArgumentException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                TransferStatus.fromString("garbage");
            }
        });
    }
}
