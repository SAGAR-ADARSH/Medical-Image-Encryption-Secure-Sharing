package com.medicalsecurity.network;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferManifest;
import com.medicalsecurity.model.TransferStatus;
import com.medicalsecurity.model.User;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.security.AuthenticationException;
import com.medicalsecurity.security.AuthorizationException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.List;

/**
 * Receiver-side transfer service (TCP): accepts encrypted payloads from
 * senders, serves incoming transfers to addressed recipients and records
 * lifecycle updates. Identity and authorization are re-checked server-side
 * for every command.
 */
public final class TransferServer extends Thread {

    private final ServerContext context;
    private final java.net.ServerSocket serverSocket;

    public TransferServer(ServerContext context, java.net.ServerSocket serverSocket) {
        super("transfer-server");
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
                }, "transfer-connection");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    System.err.println("[transfer] accept failed: " + e.getMessage());
                }
            }
        }
    }

    void handleConnection(Socket socket) {
        String remoteIp = String.valueOf(socket.getRemoteSocketAddress());
        try {
            MessageIO.configure(socket, context.config.getSocketTimeoutMs());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            int version = in.readInt();
            if (version != Protocol.PROTOCOL_VERSION) {
                out.writeInt(Protocol.STATUS_BAD_REQUEST);
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
            // Normal disconnect/timeout path.
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
    }

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
                    context.auth.logout(MessageIO.readString(in), remoteIp);
                    out.writeInt(Protocol.STATUS_OK);
                    return false;
                case Protocol.CMD_SUBMIT_TRANSFER:
                    return handleSubmit(in, out, remoteIp);
                case Protocol.CMD_LIST_INCOMING:
                    return handleList(in, out, true);
                case Protocol.CMD_LIST_OUTGOING:
                    return handleList(in, out, false);
                case Protocol.CMD_LIST_ALL_TRANSFERS:
                    return handleListAll(in, out);
                case Protocol.CMD_GET_TRANSFER:
                    return handleGetTransfer(in, out);
                case Protocol.CMD_DOWNLOAD_PAYLOAD:
                    return handleDownload(in, out);
                case Protocol.CMD_REJECT_TRANSFER:
                    return handleReject(in, out, remoteIp);
                case Protocol.CMD_MARK_STATUS:
                    return handleMarkStatus(in, out, remoteIp);
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

    /**
     * Receives manifest + wrapped key + ciphertext. The manifest is rebuilt
     * from the wire and validated; the authenticated session - not the
     * manifest - determines who the sender is.
     */
    private boolean handleSubmit(DataInputStream in, DataOutputStream out, String remoteIp) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User sender = context.auth.requireFreshUser(session);

        byte[] manifestBytes = MessageIO.readBytes(in, 64 * 1024);
        byte[] wrappedKey = MessageIO.readBytes(in, 4096);
        byte[] ciphertext = MessageIO.readBoundedPayload(in, context.config.getMaxFileBytes());

        TransferManifest manifest;
        try {
            manifest = TransferManifest.read(new DataInputStream(new ByteArrayInputStream(manifestBytes)));
            manifest.validate();
        } catch (Exception e) {
            out.writeInt(Protocol.STATUS_BAD_REQUEST);
            MessageIO.writeString(out, "Invalid transfer manifest: " + safeMessage(e));
            return true;
        }

        long id = context.transfers.receiveIncoming(sender, manifest, wrappedKey, ciphertext);
        out.writeInt(Protocol.STATUS_OK);
        out.writeLong(id);
        return true;
    }

    private boolean handleList(DataInputStream in, DataOutputStream out, boolean incoming) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        List<ImageTransfer> rows = incoming
                ? context.transfers.listIncoming(user)
                : context.transfers.listOutgoing(user);
        out.writeInt(Protocol.STATUS_OK);
        out.writeInt(rows.size());
        for (int i = 0; i < rows.size(); i++) {
            writeTransferWithNames(out, (ImageTransfer) rows.get(i));
        }
        return true;
    }

    private boolean handleListAll(DataInputStream in, DataOutputStream out) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User admin = context.auth.requireFreshUser(session);
        int limit = in.readInt();
        if (limit <= 0 || limit > 500) {
            limit = 100;
        }
        List<ImageTransfer> rows = context.transfers.listAll(admin, limit);
        out.writeInt(Protocol.STATUS_OK);
        out.writeInt(rows.size());
        for (int i = 0; i < rows.size(); i++) {
            writeTransferWithNames(out, (ImageTransfer) rows.get(i));
        }
        return true;
    }

    private boolean handleGetTransfer(DataInputStream in, DataOutputStream out) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String transferId = MessageIO.readString(in);
        ImageTransfer transfer = context.transfers.findTransfer(user, transferId);
        if (transfer == null) {
            out.writeInt(Protocol.STATUS_NOT_FOUND);
            MessageIO.writeString(out, "Unknown transfer");
            return true;
        }
        out.writeInt(Protocol.STATUS_OK);
        writeTransferWithNames(out, transfer);
        return true;
    }

    private boolean handleDownload(DataInputStream in, DataOutputStream out) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String transferId = MessageIO.readString(in);
        byte[] payload = context.transfers.downloadPayload(user, transferId);
        out.writeInt(Protocol.STATUS_OK);
        MessageIO.writeBytes(out, payload);
        return true;
    }

    private boolean handleReject(DataInputStream in, DataOutputStream out, String remoteIp) throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String transferId = MessageIO.readString(in);
        String reason = MessageIO.readString(in);
        context.transfers.rejectTransfer(user, transferId, reason, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        return true;
    }

    private boolean handleMarkStatus(DataInputStream in, DataOutputStream out, String remoteIp)
            throws Exception {
        UserSession session = context.auth.validateSession(MessageIO.readString(in));
        User user = context.auth.requireFreshUser(session);
        String transferId = MessageIO.readString(in);
        TransferStatus next = TransferStatus.fromString(MessageIO.readString(in));
        String detail = MessageIO.readString(in);
        context.transfers.markStatus(user, transferId, next, detail, remoteIp);
        out.writeInt(Protocol.STATUS_OK);
        return true;
    }

    private void writeTransferWithNames(DataOutputStream out, ImageTransfer transfer) throws IOException {
        String senderName = resolveUsername(transfer.getSenderId());
        String recipientName = resolveUsername(transfer.getRecipientId());
        WireFormat.writeTransfer(out, transfer, senderName, recipientName);
    }

    private String resolveUsername(long userId) {
        try {
            User user = context.daos.users().findById(userId);
            return user == null ? ("#" + userId) : user.getUsername();
        } catch (Exception e) {
            return "#" + userId;
        }
    }

    /** Serialises a manifest for the client-side submission path. */
    public static byte[] manifestToBytes(TransferManifest manifest) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        DataOutputStream data = new DataOutputStream(buffer);
        manifest.write(data);
        data.flush();
        return buffer.toByteArray();
    }

    private static String safeMessage(Exception e) {
        String message = e.getMessage();
        if (message == null || message.trim().isEmpty()) {
            return e.getClass().getSimpleName();
        }
        return message.length() > 200 ? message.substring(0, 200) : message;
    }
}
