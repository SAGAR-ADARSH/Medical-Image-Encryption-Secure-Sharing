package com.medicalsecurity.network;

import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.Role;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Client for the key-management/authentication service.
 */
public final class KeyServiceClient extends ProtocolClient {

    /** Public key info as served by the key registry. */
    public static final class PublicKeyInfo {
        public final long keyId;
        public final int keyVersion;
        public final String algorithm;
        public final int keySizeBits;
        public final byte[] publicKeyDer;
        public final String username;

        public PublicKeyInfo(long keyId, int keyVersion, String algorithm, int keySizeBits,
                             byte[] publicKeyDer, String username) {
            this.keyId = keyId;
            this.keyVersion = keyVersion;
            this.algorithm = algorithm;
            this.keySizeBits = keySizeBits;
            this.publicKeyDer = publicKeyDer;
            this.username = username;
        }
    }

    /** Lightweight user row for admin views. */
    public static final class UserSummary {
        public long id;
        public String username;
        public String fullName;
        public Role role;
        public boolean active;
        public long createdAtMs;
    }

    public KeyServiceClient(String host, int port, int timeoutMs) throws IOException {
        super(SslSupport.createClientSocket(
                com.medicalsecurity.config.AppConfig.load(), host, port, timeoutMs));
    }

    public KeyServiceClient(java.net.Socket socket) throws IOException {
        super(socket);
    }

    public synchronized LoginResult login(String username, String password) throws IOException {
        out.writeInt(Protocol.CMD_LOGIN);
        MessageIO.writeString(out, username);
        MessageIO.writeString(out, password);
        out.flush();
        expectOk();
        return new LoginResult(
                MessageIO.readString(in),
                in.readLong(),
                MessageIO.readString(in),
                MessageIO.readString(in),
                MessageIO.readString(in));
    }

    public synchronized void logout(String token) throws IOException {
        out.writeInt(Protocol.CMD_LOGOUT);
        MessageIO.writeString(out, token);
        out.flush();
        expectOk();
    }

    public synchronized PublicKeyInfo getPublicKey(String token, String username) throws IOException {
        out.writeInt(Protocol.CMD_GET_PUBLIC_KEY);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, username);
        out.flush();
        expectOk();
        return new PublicKeyInfo(
                in.readLong(),
                in.readInt(),
                MessageIO.readString(in),
                in.readInt(),
                MessageIO.readBytes(in, 8192),
                MessageIO.readString(in));
    }

    /**
     * Requests the wrapped key material of a transfer. Succeeds only for the
     * addressed recipient (enforced server-side).
     */
    public synchronized ProtectedKeyMaterial releaseWrappedKey(String token, String transferId)
            throws IOException {
        out.writeInt(Protocol.CMD_RELEASE_WRAPPED_KEY);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, transferId);
        out.flush();
        expectOk();
        String wrapAlg = MessageIO.readString(in);
        int keyVersion = in.readInt();
        byte[] wrapped = MessageIO.readBytes(in, 4096);
        return new ProtectedKeyMaterial(transferId, wrapAlg, wrapped, null, 0L, keyVersion);
    }

    public synchronized List<UserSummary> listUsers(String token) throws IOException {
        out.writeInt(Protocol.CMD_LIST_USERS);
        MessageIO.writeString(out, token);
        out.flush();
        expectOk();
        int count = in.readInt();
        List<UserSummary> users = new ArrayList<UserSummary>();
        for (int i = 0; i < count; i++) {
            UserSummary u = new UserSummary();
            u.id = in.readLong();
            u.username = MessageIO.readString(in);
            u.fullName = MessageIO.readString(in);
            u.role = Role.fromString(MessageIO.readString(in));
            u.active = in.readBoolean();
            u.createdAtMs = in.readLong();
            users.add(u);
        }
        return users;
    }

    public synchronized long createUser(String token, String username, String password,
                                        String fullName, String role) throws IOException {
        out.writeInt(Protocol.CMD_CREATE_USER);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, username);
        MessageIO.writeString(out, password);
        MessageIO.writeString(out, fullName);
        MessageIO.writeString(out, role);
        out.flush();
        expectOk();
        return in.readLong();
    }

    public synchronized void setUserActive(String token, long userId, boolean active) throws IOException {
        out.writeInt(Protocol.CMD_SET_USER_ACTIVE);
        MessageIO.writeString(out, token);
        out.writeLong(userId);
        out.writeBoolean(active);
        out.flush();
        expectOk();
    }

    public synchronized List<WireFormat.AuditSummary> listAudit(String token, int limit) throws IOException {
        out.writeInt(Protocol.CMD_LIST_AUDIT);
        MessageIO.writeString(out, token);
        out.writeInt(limit);
        out.flush();
        expectOk();
        int count = in.readInt();
        List<WireFormat.AuditSummary> events = new ArrayList<WireFormat.AuditSummary>();
        for (int i = 0; i < count; i++) {
            events.add(WireFormat.readAudit(in));
        }
        return events;
    }

    /** Active specialists available as transfer recipients (doctor view). */
    public synchronized List<UserSummary> listRecipients(String token) throws IOException {
        out.writeInt(Protocol.CMD_LIST_RECIPIENTS);
        MessageIO.writeString(out, token);
        out.flush();
        expectOk();
        int count = in.readInt();
        List<UserSummary> users = new ArrayList<UserSummary>();
        for (int i = 0; i < count; i++) {
            UserSummary u = new UserSummary();
            u.id = in.readLong();
            u.username = MessageIO.readString(in);
            u.fullName = MessageIO.readString(in);
            u.role = Role.fromString(MessageIO.readString(in));
            u.active = in.readBoolean();
            u.createdAtMs = in.readLong();
            users.add(u);
        }
        return users;
    }
}
