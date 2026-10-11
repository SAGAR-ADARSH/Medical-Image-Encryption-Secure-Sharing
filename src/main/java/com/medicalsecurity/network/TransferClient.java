package com.medicalsecurity.network;

import com.medicalsecurity.model.TransferManifest;
import com.medicalsecurity.model.TransferStatus;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Client for the receiver-side transfer service (used by both senders and
 * recipients).
 */
public final class TransferClient extends ProtocolClient {

    public TransferClient(String host, int port, int timeoutMs) throws IOException {
        super(SslSupport.createClientSocket(
                com.medicalsecurity.config.AppConfig.load(), host, port, timeoutMs));
    }

    public TransferClient(java.net.Socket socket) throws IOException {
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

    /** Submits manifest + wrapped key + ciphertext to the receiving service. */
    public synchronized long submitTransfer(String token, TransferManifest manifest,
                                            byte[] wrappedKey, byte[] ciphertext) throws IOException {
        out.writeInt(Protocol.CMD_SUBMIT_TRANSFER);
        MessageIO.writeString(out, token);
        MessageIO.writeBytes(out, TransferServer.manifestToBytes(manifest));
        MessageIO.writeBytes(out, wrappedKey);
        out.writeInt(ciphertext.length);
        out.write(ciphertext);
        out.flush();
        expectOk();
        return in.readLong();
    }

    public synchronized List<WireFormat.TransferSummary> listIncoming(String token) throws IOException {
        return list(token, Protocol.CMD_LIST_INCOMING);
    }

    public synchronized List<WireFormat.TransferSummary> listOutgoing(String token) throws IOException {
        return list(token, Protocol.CMD_LIST_OUTGOING);
    }

    public synchronized List<WireFormat.TransferSummary> listAllTransfers(String token, int limit)
            throws IOException {
        out.writeInt(Protocol.CMD_LIST_ALL_TRANSFERS);
        MessageIO.writeString(out, token);
        out.writeInt(limit);
        out.flush();
        expectOk();
        return readSummaries();
    }

    private List<WireFormat.TransferSummary> list(String token, int command) throws IOException {
        out.writeInt(command);
        MessageIO.writeString(out, token);
        out.flush();
        expectOk();
        return readSummaries();
    }

    private List<WireFormat.TransferSummary> readSummaries() throws IOException {
        int count = in.readInt();
        List<WireFormat.TransferSummary> rows = new ArrayList<WireFormat.TransferSummary>();
        for (int i = 0; i < count; i++) {
            rows.add(WireFormat.readTransfer(in));
        }
        return rows;
    }

    public synchronized WireFormat.TransferSummary getTransfer(String token, String transferId)
            throws IOException {
        out.writeInt(Protocol.CMD_GET_TRANSFER);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, transferId);
        out.flush();
        int status = readStatus();
        if (status == Protocol.STATUS_NOT_FOUND) {
            readErrorMessage(); // keep the stream in sync
            return null;
        }
        if (status != Protocol.STATUS_OK) {
            throw new IOException("ERROR:" + readErrorMessage());
        }
        return WireFormat.readTransfer(in);
    }

    /** Downloads the encrypted payload (recipient/admin only). */
    public synchronized byte[] downloadPayload(String token, String transferId) throws IOException {
        out.writeInt(Protocol.CMD_DOWNLOAD_PAYLOAD);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, transferId);
        out.flush();
        expectOk();
        return MessageIO.readBytes(in);
    }

    public synchronized void rejectTransfer(String token, String transferId, String reason)
            throws IOException {
        out.writeInt(Protocol.CMD_REJECT_TRANSFER);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, transferId);
        MessageIO.writeString(out, reason);
        out.flush();
        expectOk();
    }

    public synchronized void markStatus(String token, String transferId, TransferStatus status,
                                        String detail) throws IOException {
        out.writeInt(Protocol.CMD_MARK_STATUS);
        MessageIO.writeString(out, token);
        MessageIO.writeString(out, transferId);
        MessageIO.writeString(out, status.name());
        MessageIO.writeString(out, detail);
        out.flush();
        expectOk();
    }
}
