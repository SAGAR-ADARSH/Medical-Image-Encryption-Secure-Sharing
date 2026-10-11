package com.medicalsecurity.network;

import com.medicalsecurity.config.AppConfig;
import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.crypto.KeystoreService;
import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.DaoFactory;
import com.medicalsecurity.dao.Database;
import com.medicalsecurity.security.PathGuard;
import com.medicalsecurity.security.SessionManager;
import com.medicalsecurity.service.AuditService;
import com.medicalsecurity.service.AuthService;
import com.medicalsecurity.service.KeyManagementService;
import com.medicalsecurity.service.ReceiverDecryptionService;
import com.medicalsecurity.service.SenderEncryptionService;
import com.medicalsecurity.service.StorageService;
import com.medicalsecurity.service.TransferService;
import com.medicalsecurity.service.UserAdminService;

/**
 * Wires the backend services together for the server processes. One context
 * is shared by the key-management listener and the transfer listener.
 */
public final class ServerContext {

    public final AppConfig config;
    public final Database database;
    public final DaoFactory daos;
    public final SessionManager sessions;
    public final PasswordHasher passwordHasher;
    public final CryptoEngine crypto;
    public final KeyProtector keyProtector;
    public final KeystoreService keystoreService;
    public final StorageService storage;
    public final AuditService audit;
    public final AuthService auth;
    public final UserAdminService userAdmin;
    public final KeyManagementService keyManagement;
    public final TransferService transfers;
    public final SenderEncryptionService senderEncryption;
    public final ReceiverDecryptionService receiverDecryption;

    public ServerContext(AppConfig config) {
        this.config = config;
        this.database = Database.fromConfig(config);
        this.daos = new DaoFactory(database);
        this.sessions = new SessionManager();
        this.passwordHasher = new PasswordHasher(config.getPbkdf2Iterations());
        this.crypto = new CryptoEngine();
        this.keyProtector = new KeyProtector();
        this.keystoreService = new KeystoreService(config.getKeystoreDir(), config.getKeystorePassword());
        this.storage = new StorageService(new PathGuard(config.getStorageDir()), config.getMaxFileBytes());
        this.audit = new AuditService(daos.auditLogs());
        this.auth = new AuthService(daos.users(), passwordHasher, sessions, audit);
        this.userAdmin = new UserAdminService(daos.users(), daos.publicKeys(), passwordHasher,
                keystoreService, audit);
        this.keyManagement = new KeyManagementService(daos, audit);
        this.transfers = new TransferService(daos, storage, audit, config.getMaxFileBytes());
        this.senderEncryption = new SenderEncryptionService(crypto, keyProtector, config.getMaxFileBytes());
        this.receiverDecryption = new ReceiverDecryptionService(crypto, keyProtector);
    }
}
