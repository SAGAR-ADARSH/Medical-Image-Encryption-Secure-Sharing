package com.medicalsecurity.security;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Role/authorization tests (spec section 11): permission decisions are made
 * server-side from roles + resource ownership, and violations raise
 * AuthorizationException.
 */
class AuthorizationTest {

    private static User user(long id, String name, Role role) {
        return new User(id, name, name, role, true, System.currentTimeMillis(), "$pbkdf2-sha512$h");
    }

    private static User inactiveUser(long id, String name, Role role) {
        return new User(id, name, name, role, false, System.currentTimeMillis(), "$pbkdf2-sha512$h");
    }

    private static ImageTransfer transfer(long senderId, long recipientId) {
        final ImageTransfer t = new ImageTransfer();
        t.setId(10L);
        t.setTransferId("t-1");
        t.setSenderId(senderId);
        t.setRecipientId(recipientId);
        t.setOriginalFilename("scan.png");
        t.setStatus(TransferStatus.RECEIVED);
        t.setCreatedAtMs(System.currentTimeMillis());
        t.setUpdatedAtMs(System.currentTimeMillis());
        return t;
    }

    @Test
    @DisplayName("Only doctors may send; only specialists may receive")
    void sendAndReceivePermissions() {
        AuthorizationService.requireCanSend(user(1, "d", Role.DOCTOR));
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireCanSend(user(2, "s", Role.SPECIALIST));
            }
        });
        AuthorizationService.requireCanReceive(user(3, "s", Role.SPECIALIST));
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireCanReceive(user(4, "d", Role.DOCTOR));
            }
        });
    }

    @Test
    @DisplayName("Only administrators may manage users")
    void adminPermission() {
        AuthorizationService.requireAdmin(user(1, "a", Role.ADMIN));
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireAdmin(user(2, "d", Role.DOCTOR));
            }
        });
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireAdmin(user(3, "s", Role.SPECIALIST));
            }
        });
    }

    @Test
    @DisplayName("Access is granted only to the sender or the addressed recipient")
    void accessOnlyToSenderOrRecipient() {
        final ImageTransfer t = transfer(1L, 2L);
        AuthorizationService.requireParticipantOrAdmin(user(1, "doctor1", Role.DOCTOR), t);
        AuthorizationService.requireParticipantOrAdmin(user(2, "specialist1", Role.SPECIALIST), t);
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireParticipantOrAdmin(user(3, "specialist2", Role.SPECIALIST), t);
            }
        });
    }

    @Test
    @DisplayName("Only the addressed recipient may decrypt or request the wrapped key")
    void decryptAndKeyReleasePermissions() {
        final ImageTransfer t = transfer(1L, 2L);
        AuthorizationService.requireDecryptPermission(user(2, "specialist1", Role.SPECIALIST), t);
        AuthorizationService.requireKeyReleasePermission(user(2, "specialist1", Role.SPECIALIST), t);
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireDecryptPermission(user(3, "specialist2", Role.SPECIALIST), t);
            }
        });
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireKeyReleasePermission(user(4, "doctor1", Role.DOCTOR), t);
            }
        });
    }

    @Test
    @DisplayName("Sender identity cannot be forged in requests")
    void senderIdentityCannotBeForged() {
        AuthorizationService.requireSenderIdentity(user(1, "doctor1", Role.DOCTOR), 1L);
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireSenderIdentity(user(1, "doctor1", Role.DOCTOR), 99L);
            }
        });
    }

    @Test
    @DisplayName("Inactive accounts are rejected")
    void inactiveUsersRejected() {
        final User inactive = inactiveUser(1, "d", Role.DOCTOR);
        assertThrows(AuthorizationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                AuthorizationService.requireActive(inactive);
            }
        });
    }

    @Test
    @DisplayName("Role helpers classify privileges correctly")
    void roleClassification() {
        assertTrue(Role.ADMIN.isAdmin());
        assertFalse(Role.DOCTOR.isAdmin());
        assertTrue(Role.DOCTOR.canSendTransfers());
        assertTrue(Role.ADMIN.canSendTransfers());
        assertFalse(Role.SPECIALIST.canSendTransfers());
        assertTrue(Role.SPECIALIST.canReceiveTransfers());
        assertFalse(Role.DOCTOR.canReceiveTransfers());
    }
}
