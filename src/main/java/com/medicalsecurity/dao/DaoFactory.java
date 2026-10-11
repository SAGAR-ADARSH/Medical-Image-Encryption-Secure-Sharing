package com.medicalsecurity.dao;

/**
 * Factory for the JDBC DAO family sharing one {@link Database} handle.
 */
public final class DaoFactory {

    private final Database database;
    private final UserDAO userDAO;
    private final TransferDAO transferDAO;
    private final KeyRecordDAO keyRecordDAO;
    private final AuditLogDAO auditLogDAO;
    private final PublicKeyDAO publicKeyDAO;

    public DaoFactory(Database database) {
        this.database = database;
        this.userDAO = new JdbcUserDAO(database);
        this.transferDAO = new JdbcTransferDAO(database);
        this.keyRecordDAO = new JdbcKeyRecordDAO(database);
        this.auditLogDAO = new JdbcAuditLogDAO(database);
        this.publicKeyDAO = new JdbcPublicKeyDAO(database);
    }

    public Database getDatabase() {
        return database;
    }

    public UserDAO users() {
        return userDAO;
    }

    public TransferDAO transfers() {
        return transferDAO;
    }

    public KeyRecordDAO keys() {
        return keyRecordDAO;
    }

    public AuditLogDAO auditLogs() {
        return auditLogDAO;
    }

    public PublicKeyDAO publicKeys() {
        return publicKeyDAO;
    }
}
