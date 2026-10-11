package com.medicalsecurity.security;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;

/**
 * Central, backend-enforced role/permission checks. The JavaFX UI also hides
 * inapplicable controls, but these checks are the actual enforcement point -
 * every service and socket command calls them before touching data.
 */
public final class AuthorizationService {

    private AuthorizationService() {
    }

    public static void requireActive(User user) {
        if (user == null) {
            throw new AuthorizationException("No user in context");
        }
        if (!user.isActive()) {
            throw new AuthorizationException("Account is deactivated");
        }
    }

    public static void requireAdmin(User user) {
        requireActive(user);
        if (user.getRole() != Role.ADMIN) {
            throw new AuthorizationException("Administrator role required");
        }
    }

    public static void requireCanSend(User user) {
        requireActive(user);
        if (!user.getRole().canSendTransfers()) {
            throw new AuthorizationException("Only doctors may send image transfers");
        }
    }

    public static void requireCanReceive(User user) {
        requireActive(user);
        if (!user.getRole().canReceiveTransfers()) {
            throw new AuthorizationException("Only specialists may receive image transfers");
        }
    }

    /**
     * Doctors may not impersonate specialists (or each other): the sender ID on
     * a transfer is taken from the authenticated session, never from client
     * input. This check is applied again on the receiving side.
     */
    public static void requireSenderIdentity(User authenticatedSender, long claimedSenderId) {
        requireCanSend(authenticatedSender);
        if (authenticatedSender.getId() != claimedSenderId) {
            throw new AuthorizationException(
                    "Sender identity mismatch: transfers must be sent by the authenticated account");
        }
    }

    /** Only the addressed recipient (or an admin) may act on a transfer. */
    public static void requireRecipientOrAdmin(User user, ImageTransfer transfer) {
        requireActive(user);
        if (transfer == null) {
            throw new AuthorizationException("Unknown transfer");
        }
        if (user.getRole() == Role.ADMIN) {
            return;
        }
        if (user.getId() != transfer.getRecipientId()) {
            throw new AuthorizationException(
                    "Access denied: this transfer is addressed to a different recipient");
        }
    }

    /** Sender, recipient or admin may view transfer metadata. */
    public static void requireParticipantOrAdmin(User user, ImageTransfer transfer) {
        requireActive(user);
        if (transfer == null) {
            throw new AuthorizationException("Unknown transfer");
        }
        if (user.getRole() == Role.ADMIN) {
            return;
        }
        if (user.getId() != transfer.getRecipientId() && user.getId() != transfer.getSenderId()) {
            throw new AuthorizationException("Access denied: you are not a participant of this transfer");
        }
    }

    /** Decryption is allowed for the addressed recipient only (not even the sender). */
    public static void requireDecryptPermission(User user, ImageTransfer transfer) {
        requireActive(user);
        if (transfer == null) {
            throw new AuthorizationException("Unknown transfer");
        }
        if (user.getId() != transfer.getRecipientId()) {
            throw new AuthorizationException(
                    "Access denied: only the addressed recipient may decrypt this transfer");
        }
    }

    /** Key release follows the decrypt rule: recipient only. */
    public static void requireKeyReleasePermission(User user, ImageTransfer transfer) {
        requireDecryptPermission(user, transfer);
    }
}
