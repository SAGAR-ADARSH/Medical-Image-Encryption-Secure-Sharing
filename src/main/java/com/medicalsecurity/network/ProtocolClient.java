package com.medicalsecurity.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * Client-side helper: one socket, request/response exchanges with the
 * protocol framing. Concrete clients ({@link KeyServiceClient},
 * {@link TransferClient}) build on this class.
 */
public class ProtocolClient implements java.io.Closeable {

    /** Login result shared by both services. */
    public static final class LoginResult {
        public final String token;
        public final long userId;
        public final String username;
        public final String role;
        public final String fullName;

        public LoginResult(String token, long userId, String username, String role, String fullName) {
            this.token = token;
            this.userId = userId;
            this.username = username;
            this.role = role;
            this.fullName = fullName;
        }
    }

    protected final Socket socket;
    protected final DataInputStream in;
    protected final DataOutputStream out;

    protected ProtocolClient(Socket socket) throws IOException {
        this.socket = socket;
        this.in = new DataInputStream(socket.getInputStream());
        this.out = new DataOutputStream(socket.getOutputStream());
        out.writeInt(Protocol.PROTOCOL_VERSION);
        out.flush();
    }

    /** Reads the standard response header; throws on non-OK statuses. */
    protected void expectOk() throws IOException {
        int status = in.readInt();
        if (status == Protocol.STATUS_OK) {
            return;
        }
        String message = MessageIO.readString(in);
        switch (status) {
            case Protocol.STATUS_AUTH_REQUIRED:
                throw new IOException("AUTH:" + message);
            case Protocol.STATUS_DENIED:
                throw new IOException("DENIED:" + message);
            case Protocol.STATUS_NOT_FOUND:
                throw new IOException("NOT_FOUND:" + message);
            case Protocol.STATUS_BAD_REQUEST:
                throw new IOException("BAD_REQUEST:" + message);
            default:
                throw new IOException("ERROR:" + message);
        }
    }

    /** Reads the header and returns the raw status (for multi-case responses). */
    protected int readStatus() throws IOException {
        return in.readInt();
    }

    protected String readErrorMessage() throws IOException {
        return MessageIO.readString(in);
    }

    @Override
    public synchronized void close() {
        try {
            socket.close();
        } catch (IOException ignored) {
            // best effort
        }
    }
}
