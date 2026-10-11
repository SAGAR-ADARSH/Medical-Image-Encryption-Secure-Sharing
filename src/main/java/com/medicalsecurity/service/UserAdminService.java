package com.medicalsecurity.service;

import com.medicalsecurity.crypto.KeystoreService;
import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.DuplicateUserException;
import com.medicalsecurity.dao.PublicKeyDAO;
import com.medicalsecurity.dao.UserDAO;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;
import com.medicalsecurity.security.AuthorizationService;
import com.medicalsecurity.util.Validation;

import java.security.PublicKey;
import java.util.List;

/**
 * Administrator user management: create accounts (with role assignment),
 * activate/deactivate them and provision recipient key pairs. All operations
 * are backend-checked for the ADMIN role regardless of who calls them.
 */
public final class UserAdminService {

    private final UserDAO userDAO;
    private final PublicKeyDAO publicKeyDAO;
    private final PasswordHasher passwordHasher;
    private final KeystoreService keystoreService;
    private final AuditService audit;

    public UserAdminService(UserDAO userDAO, PublicKeyDAO publicKeyDAO, PasswordHasher passwordHasher,
                            KeystoreService keystoreService, AuditService audit) {
        this.userDAO = userDAO;
        this.publicKeyDAO = publicKeyDAO;
        this.passwordHasher = passwordHasher;
        this.keystoreService = keystoreService;
        this.audit = audit;
    }

    /**
     * Creates an account, hashes the password, provisions the user's RSA key
     * pair into a PKCS#12 keystore and registers the PUBLIC key.
     */
    public User createUser(User admin, String username, String passwordPlainText,
                           String fullName, Role role, String sourceIp) {
        AuthorizationService.requireAdmin(admin);
        Validation.requireValidUsername(username);
        Validation.requireValidFullName(fullName);
        if (role == null) {
            throw new IllegalArgumentException("Role is required");
        }
        if (passwordPlainText == null || passwordPlainText.length() < 8) {
            throw new IllegalArgumentException("Password must be at least 8 characters");
        }
        String passwordHash = passwordHasher.hash(passwordPlainText.toCharArray());
        long userId;
        try {
            userId = userDAO.insert(username, passwordHash, fullName, role, true);
        } catch (DuplicateUserException e) {
            audit.failure(AuditEvent.USER_CREATED, admin.getUsername(), Long.valueOf(admin.getId()),
                    null, "Duplicate username " + username, sourceIp);
            throw e;
        } catch (java.sql.SQLException e) {
            audit.failure(AuditEvent.USER_CREATED, admin.getUsername(), Long.valueOf(admin.getId()),
                    null, "Database error creating " + username, sourceIp);
            throw new IllegalStateException("Could not create account", e);
        }

        // Provision the key pair; if this fails the account is rolled back by
        // deleting the row (keystores and DB rows must stay consistent).
        try {
            PublicKey publicKey = keystoreService.provisionKeyPair(username);
            publicKeyDAO.insert(userId, KeystoreService.KEY_ALGORITHM, KeystoreService.KEY_SIZE_BITS,
                    publicKey.getEncoded(), 1, username + ".p12");
        } catch (Exception e) {
            try {
                userDAO.setActive(userId, false);
                keystoreService.deleteKeyStore(username);
            } catch (Exception cleanup) {
                // ignore secondary failures
            }
            audit.failure(AuditEvent.USER_CREATED, admin.getUsername(), Long.valueOf(admin.getId()),
                    null, "Key provisioning failed for " + username, sourceIp);
            throw new IllegalStateException("Account created but key provisioning failed; account left deactivated");
        }

        audit.success(AuditEvent.USER_CREATED, admin.getUsername(), Long.valueOf(admin.getId()),
                null, "Created " + role + " account '" + username + "'", sourceIp);
        audit.success(AuditEvent.KEY_REGISTERED, username, Long.valueOf(userId),
                null, "RSA-" + KeystoreService.KEY_SIZE_BITS + " key pair provisioned", sourceIp);
        try {
            return userDAO.findById(userId);
        } catch (Exception e) {
            throw new IllegalStateException("Account created but lookup failed");
        }
    }

    public void setActive(User admin, long userId, boolean active, String sourceIp) {
        AuthorizationService.requireAdmin(admin);
        try {
            boolean changed = userDAO.setActive(userId, active);
            if (!changed) {
                throw new IllegalArgumentException("Unknown user id " + userId);
            }
            audit.success(active ? AuditEvent.USER_ENABLED : AuditEvent.USER_DISABLED,
                    admin.getUsername(), Long.valueOf(admin.getId()), null,
                    (active ? "Enabled" : "Disabled") + " user id " + userId, sourceIp);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Could not update account state");
        }
    }

    public List<User> listUsers(User admin) {
        AuthorizationService.requireAdmin(admin);
        try {
            return userDAO.findAll();
        } catch (Exception e) {
            throw new IllegalStateException("Could not list users");
        }
    }

    public List<User> listRecipients(User admin) {
        AuthorizationService.requireAdmin(admin);
        try {
            return userDAO.findByRole(Role.SPECIALIST);
        } catch (Exception e) {
            throw new IllegalStateException("Could not list recipients");
        }
    }

    /**
     * Installation-time bootstrap: creates the FIRST administrator account.
     * This path is only used by {@link AdminBootstrap} (before any admin
     * exists); every other user-creation path requires a logged-in admin.
     */
    public User createInitialAdmin(String username, String passwordPlainText,
                                   String fullName, String sourceIp) {
        Validation.requireValidUsername(username);
        Validation.requireValidFullName(fullName);
        if (passwordPlainText == null || passwordPlainText.length() < 8) {
            throw new IllegalArgumentException("Administrator password must be at least 8 characters");
        }
        String passwordHash = passwordHasher.hash(passwordPlainText.toCharArray());
        long userId;
        try {
            userId = userDAO.insert(username, passwordHash, fullName, Role.ADMIN, true);
            PublicKey publicKey = keystoreService.provisionKeyPair(username);
            publicKeyDAO.insert(userId, KeystoreService.KEY_ALGORITHM, KeystoreService.KEY_SIZE_BITS,
                    publicKey.getEncoded(), 1, username + ".p12");
        } catch (DuplicateUserException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("Administrator bootstrap failed: " + e.getMessage(), e);
        }
        audit.success(AuditEvent.USER_CREATED, username, Long.valueOf(userId), null,
                "Initial administrator account created", sourceIp);
        try {
            return userDAO.findById(userId);
        } catch (Exception e) {
            throw new IllegalStateException("Administrator created but lookup failed");
        }
    }
}
