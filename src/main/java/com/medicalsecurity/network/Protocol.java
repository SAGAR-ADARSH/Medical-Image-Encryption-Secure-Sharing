package com.medicalsecurity.network;

/**
 * Wire protocol constants shared by the key-management server, the transfer
 * server and their clients.
 *
 * <p>Frame layout (DataOutputStream over a TCP socket):
 * <pre>
 *   request  : int command, &lt;command-specific fields&gt;
 *   response : int status, &lt;status-specific fields&gt;
 * </pre>
 * All variable-length byte arrays are length-prefixed with a 32-bit int and
 * capped by {@link MessageIO#MAX_FRAME_BYTES}.
 */
public final class Protocol {

    private Protocol() {
    }

    public static final int PROTOCOL_VERSION = 1;

    // ------------------------------------------------------------------
    // Response status codes
    // ------------------------------------------------------------------
    public static final int STATUS_OK = 0;
    public static final int STATUS_ERROR = 1;
    public static final int STATUS_AUTH_REQUIRED = 2;
    public static final int STATUS_DENIED = 3;
    public static final int STATUS_NOT_FOUND = 4;
    public static final int STATUS_BAD_REQUEST = 5;

    // ------------------------------------------------------------------
    // Key-management service commands (port KEYMGR_PORT)
    // ------------------------------------------------------------------
    public static final int CMD_PING = 1;
    public static final int CMD_LOGIN = 2;
    public static final int CMD_LOGOUT = 3;
    public static final int CMD_GET_PUBLIC_KEY = 4;
    public static final int CMD_RELEASE_WRAPPED_KEY = 5;
    public static final int CMD_LIST_USERS = 6;
    public static final int CMD_CREATE_USER = 7;
    public static final int CMD_SET_USER_ACTIVE = 8;
    public static final int CMD_LIST_AUDIT = 9;
    public static final int CMD_LIST_RECIPIENTS = 10;

    // ------------------------------------------------------------------
    // Transfer service commands (port TRANSFER_PORT)
    // ------------------------------------------------------------------
    public static final int CMD_SUBMIT_TRANSFER = 20;
    public static final int CMD_LIST_INCOMING = 21;
    public static final int CMD_LIST_OUTGOING = 22;
    public static final int CMD_DOWNLOAD_PAYLOAD = 23;
    public static final int CMD_REJECT_TRANSFER = 24;
    public static final int CMD_MARK_STATUS = 25;
    public static final int CMD_GET_TRANSFER = 26;
    public static final int CMD_LIST_ALL_TRANSFERS = 27;
}
