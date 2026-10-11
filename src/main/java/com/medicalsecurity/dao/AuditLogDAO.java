package com.medicalsecurity.dao;

import com.medicalsecurity.model.AuditEvent;

import java.sql.SQLException;
import java.util.List;

/** Append-only audit trail. */
public interface AuditLogDAO {

    void insert(AuditEvent event) throws SQLException;

    List<AuditEvent> findRecent(int limit) throws SQLException;

    List<AuditEvent> findByTransferId(String transferId) throws SQLException;

    List<AuditEvent> findByOutcome(String outcome, int limit) throws SQLException;
}
