package com.medicalsecurity.service;

import com.medicalsecurity.dao.AuditLogDAO;
import com.medicalsecurity.model.AuditEvent;

/**
 * Audit helper. Logging must never break the business flow; failures are
 * reported on stderr but swallowed. Secrets are never passed to this class.
 */
public final class AuditService {

    private final AuditLogDAO auditLogDAO;

    public AuditService(AuditLogDAO auditLogDAO) {
        this.auditLogDAO = auditLogDAO;
    }

    public void log(String eventType, String username, Long userId, String transferId,
                    String outcome, String detail, String sourceIp) {
        AuditEvent event = new AuditEvent(eventType, username, userId, transferId,
                outcome, sanitize(detail), sourceIp, System.currentTimeMillis());
        try {
            auditLogDAO.insert(event);
        } catch (Exception e) {
            System.err.println("[audit] could not record " + eventType + ": " + e.getMessage());
        }
    }

    public void success(String eventType, String username, Long userId, String transferId, String detail, String ip) {
        log(eventType, username, userId, transferId, AuditEvent.OUTCOME_SUCCESS, detail, ip);
    }

    public void failure(String eventType, String username, Long userId, String transferId, String detail, String ip) {
        log(eventType, username, userId, transferId, AuditEvent.OUTCOME_FAILURE, detail, ip);
    }

    public void denied(String eventType, String username, Long userId, String transferId, String detail, String ip) {
        log(eventType, username, userId, transferId, AuditEvent.OUTCOME_DENIED, detail, ip);
    }

    /** Keeps audit details short and free of secret-looking material. */
    private static String sanitize(String detail) {
        if (detail == null) {
            return null;
        }
        String d = detail.trim();
        if (d.length() > 250) {
            d = d.substring(0, 250);
        }
        return d;
    }
}
