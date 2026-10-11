package com.medicalsecurity.model;

/**
 * One audit-trail entry. Audit rows never contain secret material: no
 * passwords, no keys, no image bytes - only who did what, to which transfer,
 * and whether it succeeded.
 */
public final class AuditEvent {

    private long id;
    private String eventType;
    private String username;
    private Long userId;
    private String transferId;
    private String outcome;
    private String detail;
    private String sourceIp;
    private long createdAtMs;

    public AuditEvent() {
    }

    public AuditEvent(String eventType, String username, Long userId, String transferId,
                      String outcome, String detail, String sourceIp, long createdAtMs) {
        this.eventType = eventType;
        this.username = username;
        this.userId = userId;
        this.transferId = transferId;
        this.outcome = outcome;
        this.detail = detail;
        this.sourceIp = sourceIp;
        this.createdAtMs = createdAtMs;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getTransferId() {
        return transferId;
    }

    public void setTransferId(String transferId) {
        this.transferId = transferId;
    }

    public String getOutcome() {
        return outcome;
    }

    public void setOutcome(String outcome) {
        this.outcome = outcome;
    }

    public String getDetail() {
        return detail;
    }

    public void setDetail(String detail) {
        this.detail = detail;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public void setSourceIp(String sourceIp) {
        this.sourceIp = sourceIp;
    }

    public long getCreatedAtMs() {
        return createdAtMs;
    }

    public void setCreatedAtMs(long createdAtMs) {
        this.createdAtMs = createdAtMs;
    }

    // Convenience constants for event types used across the code base.
    public static final String AUTH_OK = "AUTH_OK";
    public static final String AUTH_FAIL = "AUTH_FAIL";
    public static final String USER_CREATED = "USER_CREATED";
    public static final String USER_DISABLED = "USER_DISABLED";
    public static final String USER_ENABLED = "USER_ENABLED";
    public static final String KEY_REGISTERED = "KEY_REGISTERED";
    public static final String KEY_RELEASE = "KEY_RELEASE";
    public static final String KEY_RELEASE_DENIED = "KEY_RELEASE_DENIED";
    public static final String TRANSFER_CREATED = "TRANSFER_CREATED";
    public static final String TRANSFER_SENT = "TRANSFER_SENT";
    public static final String TRANSFER_RECV = "TRANSFER_RECV";
    public static final String TRANSFER_REJECTED = "TRANSFER_REJECTED";
    public static final String TRANSFER_FAILED = "TRANSFER_FAILED";
    public static final String ENCRYPT_OK = "ENCRYPT_OK";
    public static final String DECRYPT_OK = "DECRYPT_OK";
    public static final String DECRYPT_FAIL = "DECRYPT_FAIL";
    public static final String INTEGRITY_OK = "INTEGRITY_OK";
    public static final String INTEGRITY_FAIL = "INTEGRITY_FAIL";
    public static final String ACCESS_DENIED = "ACCESS_DENIED";

    public static final String OUTCOME_SUCCESS = "SUCCESS";
    public static final String OUTCOME_FAILURE = "FAILURE";
    public static final String OUTCOME_DENIED = "DENIED";
}
