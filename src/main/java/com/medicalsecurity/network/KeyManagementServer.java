package com.medicalsecurity.network;

import com.medicalsecurity.dao.PublicKeyRecord;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.security.AuthenticationException;
import com.medicalsecurity.security.AuthorizationException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.List;

/**
 * Key-management and authentication service (TCP).
 *
 * <p>Handles: login/logout, user administration, public-key directory and
 * wrapped-key release. Every command is executed against the authenticated
 * session; client-supplied identities are never trusted.
 */
public final class KeyManagementServer extends Thread {

    private final ServerContext context;
    private final java.net.ServerSocket serverSocket;

    public KeyManagementServer(ServerContext context, java.net.ServerSocket serverSocket) {
        super("key-management-server");
        this.context = context;
        this.serverSocket = serverSocket;
        setDaemon(true);
    }

    @Override
    public void run() {
        while (!serverSocket.isClosed()) {
            try {
                final Socket socket = serverSocket.accept();
                Thread worker = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        handleConnection(socket);
                    }
                }, "keymgmt-connection");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    System.err.println("[keymgmt] accept failed: " + e.getMessage());
                }
            }
        }
    }

    void handleConnection(Socket socket) {
        DataInputStream in = null;
        DataOutputStream out = null;
        String remoteIp = String.valueOf(socket.getRemoteSocketAddress());
        try {
            MessageIO.configure(socket, context.config.getSocketTimeoutMs());
            in = new DataInputStream(socket.getInputStream());
            out = new DataOutputStream(socket.getOutputStream());
            int version = in.readInt();
            if (version != Protocol.PROTOCOL_VERSION) {
                MessageIO.writeString(out, "Unsupported protocol version");
                out.flush();
                return;
            }
            while (true) {
                int command = in.readInt();
                boolean keepAlive = dispatch(command, in, out, remoteIp);
                out.flush();
                if (!keepAlive) {
                    break;
                }
            }
        } catch (IOException e) {
            // Connection closed or timed out - normal for this protocol.
        } finally {
            closeQuietly(socket);
        }
    }

    /**
     * Executes one command. Returns {@code false} when the connection should
     * be closed (logout / fatal protocol error).
     */
    private boolean dispatch(int command, DataInputStream in, DataOutputStream out, String remoteIp)
            throws IOException {
        try {
            switch (command) {
                case Protocol.CMD_PING:
                    out.writeInt(Protocol.STATUS_OK);
                    return true;
                case Protocol.CMD_LOGIN:
                    return handleLogin(in, out, remoteIp);
                case Protocol.CMD_LOGOUT:
                    return handleLogout(in, out, remoteIp);
                case Protocol.CMD_GET_PUBLIC_KEY:
                    return handleGetPublicKey(in, out);
                case Protocol.CMD_RELEASE_WRAPPED_KEY:
                    return handleReleaseWrappedKey(in, out, remoteIp);
                case Protocol.CMD_LIST_USERS:
                    return handleListUsers(in, out);
                case Protocol.CMD_CREATE_USER:
                    return handleCreateUser(in, out, remoteIp);
                case Protocol.CMD_SET_USER_ACTIVE:
                    return handleSetUserActive(in, out, remoteIp);
                case Protocol.CMD_LIST_AUDIT:
                    return handleListAudit(in, out);
                case Protocol.CMD_LIST_RECIPIENTS:
                    return handleListRecipients(in, out);
                default:
                    out.writeInt(Protocol.STATUS_BAD_REQUEST);
                    MessageIO.writeString(out, "Unknown command: " + command);
                    return true;
            }
        } catch (AuthenticationException e) {
            out.writeInt(Protocol.STATUS_AUTH_REQUIRED);
            MessageIO.writeString(out, e.getMessage());
            return true;
        } catch (AuthorizationException e) {
            out.writeInt(Protocol.STATUS_DENIED);
            MessageIO.writeString(out, e.getMessage());
            return true;
        } catch (IllegalArgumentException e) {
            out.writeInt(Protocol.STATUS_BAD_REQUEST);
            MessageIO.writeString(out, e.getMessage());
            return true;
        } catch (Exception e) {
            out.writeInt(Protocol.STATUS_ERROR);
            MessageIO.writeString(out, "Request failed: " + safeMessage(e));
            return true;
        }
    }

    private boolean handleLogin(DataInputStream in, DataOutputStream out, String remoteIp) throws IOException {
        String username = MessageIO.readString(in);
        String password = MessageIO.readString(in);
        try {
            UserSession session = context.auth.login(username, password.toCharArray(), remoteIp);
            User user = context.auth.requireFreshUser(session);
            out.writeInt(Protocol.STATUS_OK);
            MessageIO.writeString(out, session.getToken());
            out.writeLong(session.getUserId());
            MessageIO.writeString(out, session.getUsername());
            MessageIO.writeString(out, session.getRole().name());
            MessageIO.writeString(out, user.getFullName());
            return true;
        } catch (AuthenticationException e) {
            out.writeInt(Protocol.STATUS_AUTH_REQUIRED);
            MessageIO.writeString(out, e.getMessage());
            return true;
        }
    }

    private boolean handleLogout(DataInputStream in, DataOutputStream out, String remoteIp) throws IOException {
        String token = MessageIO.readString(in);
        context.auth.logout(token, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        return false; // close the connection after logout
    }

    private boolean handleGetPublicKey(DataInputStream in, DataOutputStream out) throws IOException {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String username = MessageIO.readString(in);
        PublicKeyRecord record = context.keyManagement.getPublicKey(user, username);
        out.writeInt(Protocol.STATUS_OK);
        out.writeLong(record.id);
        out.writeInt(record.keyVersion);
        MessageIO.writeString(out, record.algorithm);
        out.writeInt(record.keySizeBits);
        MessageIO.writeBytes(out, record.publicKeyDer);
        MessageIO.writeString(out, record.username);
        return true;
    }

    private boolean handleReleaseWrappedKey(DataInputStream in, DataOutputStream out, String remoteIp)
            throws IOException {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String transferId = MessageIO.readString(in);
        ProtectedKeyMaterial material = context.keyManagement.releaseWrappedKey(user, transferId, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        MessageIO.writeString(out, material.getWrapAlgorithm());
        out.writeInt(material.getKeyVersion());
        MessageIO.writeBytes(out, material.getWrappedKey());
        return true;
    }

    private boolean handleListUsers(DataInputStream in, DataOutputStream out) throws IOException {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User admin = context.auth.requireFreshUser(session);
        List<User> users = context.userAdmin.listUsers(admin);
        out.writeInt(Protocol.STATUS_OK);
        out.writeInt(users.size());
        for (int i = 0; i < users.size(); i++) {
            User u = (User) users.get(i);
            out.writeLong(u.getId());
            MessageIO.writeString(out, u.getUsername());
            MessageIO.writeString(out, u.getFullName());
            MessageIO.writeString(out, u.getRole().name());
            out.writeBoolean(u.isActive());
            out.writeLong(u.getCreatedAtMs());
        }
        return true;
    }

    private boolean handleCreateUser(DataInputStream in, DataOutputStream out, String remoteIp)
            throws IOException {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User admin = context.auth.requireFreshUser(session);
        String username = MessageIO.readString(in);
        String password = MessageIO.readString(in);
        String fullName = MessageIO.readString(in);
        Role role = Role.fromString(MessageIO.readString(in));
        User created = context.userAdmin.createUser(admin, username, password, fullName, role, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        out.writeLong(created.getId());
        return true;
    }

    private boolean handleSetUserActive(DataInputStream in, DataOutputStream out, String remoteIp)
            throws IOException {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User admin = context.auth.requireFreshUser(session);
        long userId = in.readLong();
        boolean active = in.readBoolean();
        context.userAdmin.setActive(admin, userId, active, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        return true;
    }

    private boolean handleListAudit(DataInputStream in, DataOutputStream out) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User admin = context.auth.requireFreshUser(session);
        com.medicalsecurity.security.AuthorizationService.requireAdmin(admin);
        int limit = in.readInt();
        if (limit <= 0 || limit > 500) {
            limit = 100;
        }
        List<AuditEvent> events = context.daos.auditLogs().findRecent(limit);
        out.writeInt(Protocol.STATUS_OK);
        out.writeInt(events.size());
        for (int i = 0; i < events.size(); i++) {
            WireFormat.writeAudit(out, (AuditEvent) events.get(i));
        }
        return true;
    }

    /** Active specialists - the authorised recipients a doctor may address. */
    private boolean handleListRecipients(DataInputStream in, DataOutputStream out) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        com.medicalsecurity.security.AuthorizationService.requireCanSend(user);
        List<User> recipients = context.daos.users().findByRole(Role.SPECIALIST);
        out.writeInt(Protocol.STATUS_OK);
        out.writeInt(recipients.size());
        for (int i = 0; i < recipients.size(); i++) {
            User u = (User) recipients.get(i);
            out.writeLong(u.getId());
            MessageIO.writeString(out, u.getUsername());
            MessageIO.writeString(out, u.getFullName());
            MessageIO.writeString(out, u.getRole().name());
            out.writeBoolean(u.isActive());
            out.writeLong(u.getCreatedAtMs());
        }
        return true;
    }

    private static String safeMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return e.getClass().getSimpleName();
        }
        return message.length() > 200 ? message.substring(0, 200) : message;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // best effort
        }
    }
}
