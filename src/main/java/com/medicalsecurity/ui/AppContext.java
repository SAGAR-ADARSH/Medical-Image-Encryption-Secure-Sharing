package com.medicalsecurity.ui;

import com.medicalsecurity.config.AppConfig;
import com.medicalsecurity.crypto.CryptoEngine;
import com.medicalsecurity.crypto.KeyProtector;
import com.medicalsecurity.crypto.KeystoreService;
import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.AuditLogDAO;
import com.medicalsecurity.dao.DaoFactory;
import com.medicalsecurity.dao.Database;
import com.medicalsecurity.dao.JdbcAuditLogDAO;
import com.medicalsecurity.dao.SchemaInitializer;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.network.BackendServer;
import com.medicalsecurity.security.SessionManager;
import com.medicalsecurity.service.AuditService;
import com.medicalsecurity.service.AuthService;
import com.medicalsecurity.service.KeyManagementService;
import com.medicalsecurity.service.ReceiverDecryptionService;
import com.medicalsecurity.service.SenderEncryptionService;
import com.medicalsecurity.service.StorageService;
import com.medicalsecurity.service.TransferService;
import com.medicalsecurity.service.UserAdminService;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Application-wide dependency container for the desktop client.
 *
 * <p>The UI talks only to these backend service objects (the same classes the
 * socket servers use) - every permission check, crypto operation and audit
 * write therefore runs in the backend layer, never in UI code. In the default
 * single-machine setup the in-process {@link BackendServer} is started as
 * well, so the two TCP services are available for external clients.
 */
public final class AppContext {

    private static AppContext instance;

    private final AppConfig config;
    private final Database database;
    private final DaoFactory daos;
    private final PasswordHasher passwordHasher;
    private final KeystoreService keystoreService;
    private final CryptoEngine cryptoEngine;
    private final KeyProtector keyProtector;
    private final AuditService auditService;
    private final SessionManager sessionManager;
    private final AuthService authService;
    private final UserAdminService userAdminService;
    private final KeyManagementService keyManagementService;
    private final SenderEncryptionService senderEncryptionService;
    private final ReceiverDecryptionService receiverDecryptionService;
    private final TransferService transferService;
    private final StorageService storageService;
    private final BackendServer backendServer;

    private UserSession currentSession;

    private AppContext(AppConfig config) throws Exception {
        this.config = config;
        this.database = new Database(config.getDbDriver(), config.getDbUrl(),
                config.getDbUser(), config.getDbPassword());
        SchemaInitializer.applyScript(database, loadSchemaScript());
        this.daos = new DaoFactory(database);
        this.passwordHasher = new PasswordHasher();
        this.keystoreService = new KeystoreService(config.getKeystoreDir(), config.getKeystorePassword());
        this.cryptoEngine = new CryptoEngine();
        this.keyProtector = new KeyProtector();
        this.auditService = new AuditService(new JdbcAuditLogDAO(database));
        this.sessionManager = new SessionManager();
        this.authService = new AuthService(daos.users(), passwordHasher, sessionManager, auditService);
        this.userAdminService = new UserAdminService(daos.users(), daos.publicKeys(),
                passwordHasher, keystoreService, auditService);
        this.keyManagementService = new KeyManagementService(daos, auditService);
        this.storageService = new StorageService(new com.medicalsecurity.security.PathGuard(config.getStorageDir()),
                config.getMaxFileBytes());
        this.transferService = new TransferService(daos, storageService, auditService, config.getMaxFileBytes());
        this.senderEncryptionService = new SenderEncryptionService(cryptoEngine, keyProtector, config.getMaxFileBytes());
        this.receiverDecryptionService = new ReceiverDecryptionService(cryptoEngine, keyProtector);
        this.backendServer = new BackendServer(config);
    }

    /** Schema script: from the sql/ directory when running from the project, else classpath. */
    private static String loadSchemaScript() throws Exception {
        Path local = Paths.get("sql", "schema.sql");
        if (Files.isRegularFile(local)) {
            return new String(Files.readAllBytes(local), StandardCharsets.UTF_8);
        }
        return SchemaInitializer.readResource("sql/schema.sql");
    }

    public static synchronized AppContext get() {
        if (instance == null) {
            try {
                AppConfig config = AppConfig.load();
                AppContext ctx = new AppContext(config);
                ctx.backendServer.start(); // TCP key-manager + transfer services
                instance = ctx;
            } catch (Exception e) {
                throw new IllegalStateException("Application start-up failed: " + e.getMessage(), e);
            }
        }
        return instance;
    }

    public void close() {
        try {
            backendServer.stop();
        } catch (Exception ignored) {
        }
    }

    // ---- accessors ----
    public AppConfig getConfig() { return config; }
    public Database getDatabase() { return database; }
    public DaoFactory getDaos() { return daos; }
    public PasswordHasher getPasswordHasher() { return passwordHasher; }
    public KeystoreService getKeystoreService() { return keystoreService; }
    public CryptoEngine getCryptoEngine() { return cryptoEngine; }
    public KeyProtector getKeyProtector() { return keyProtector; }
    public AuditService getAuditService() { return auditService; }
    public SessionManager getSessionManager() { return sessionManager; }
    public AuthService getAuthService() { return authService; }
    public UserAdminService getUserAdminService() { return userAdminService; }
    public KeyManagementService getKeyManagementService() { return keyManagementService; }
    public SenderEncryptionService getSenderEncryptionService() { return senderEncryptionService; }
    public ReceiverDecryptionService getReceiverDecryptionService() { return receiverDecryptionService; }
    public TransferService getTransferService() { return transferService; }
    public StorageService getStorageService() { return storageService; }
    public AuditLogDAO getAuditLogDAO() { return new JdbcAuditLogDAO(database); }
    public BackendServer getBackendServer() { return backendServer; }
    public UserSession getCurrentSession() { return currentSession; }
    public void setCurrentSession(UserSession session) { this.currentSession = session; }
}
