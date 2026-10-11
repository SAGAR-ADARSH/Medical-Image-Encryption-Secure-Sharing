package com.medicalsecurity.network;

import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferStatus;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Serialisation of entity summaries for list responses. Kept deliberately
 * explicit (no reflection, no JSON library) so the wire format is auditable.
 */
public final class WireFormat {

    private WireFormat() {
    }

    public static void writeTransfer(DataOutputStream out, ImageTransfer t,
                                     String senderUsername, String recipientUsername) throws IOException {
        MessageIO.writeString(out, t.getTransferId());
        MessageIO.writeString(out, senderUsername == null ? "" : senderUsername);
        MessageIO.writeString(out, recipientUsername == null ? "" : recipientUsername);
        MessageIO.writeString(out, t.getOriginalFilename());
        MessageIO.writeString(out, t.getContentType() == null ? "" : t.getContentType());
        out.writeLong(t.getPlaintextSize());
        out.writeLong(t.getCiphertextSize());
        MessageIO.writeString(out, t.getPlaintextSha256());
        MessageIO.writeString(out, t.getAlgorithm());
        out.writeInt(t.getKeySizeBits());
        MessageIO.writeBytes(out, t.getNonce());
        out.writeInt(t.getTagBits());
        MessageIO.writeString(out, t.getStatus() == null ? "" : t.getStatus().name());
        MessageIO.writeString(out, t.getErrorDetail() == null ? "" : t.getErrorDetail());
        out.writeLong(t.getCreatedAtMs());
        out.writeLong(t.getUpdatedAtMs());
    }

    public static TransferSummary readTransfer(DataInputStream in) throws IOException {
        TransferSummary s = new TransferSummary();
        s.transferId = MessageIO.readString(in);
        s.senderUsername = MessageIO.readString(in);
        s.recipientUsername = MessageIO.readString(in);
        s.originalFilename = MessageIO.readString(in);
        s.contentType = MessageIO.readString(in);
        s.plaintextSize = in.readLong();
        s.ciphertextSize = in.readLong();
        s.plaintextSha256 = MessageIO.readString(in);
        s.algorithm = MessageIO.readString(in);
        s.keySizeBits = in.readInt();
        s.nonce = MessageIO.readBytes(in, 32);
        s.tagBits = in.readInt();
        s.status = TransferStatus.fromString(MessageIO.readString(in));
        s.errorDetail = MessageIO.readString(in);
        s.createdAtMs = in.readLong();
        s.updatedAtMs = in.readLong();
        return s;
    }

    public static void writeAudit(DataOutputStream out, AuditEvent e) throws IOException {
        out.writeLong(e.getId());
        MessageIO.writeString(out, e.getEventType());
        MessageIO.writeString(out, e.getUsername() == null ? "" : e.getUsername());
        MessageIO.writeString(out, e.getTransferId() == null ? "" : e.getTransferId());
        MessageIO.writeString(out, e.getOutcome());
        MessageIO.writeString(out, e.getDetail() == null ? "" : e.getDetail());
        MessageIO.writeString(out, e.getSourceIp() == null ? "" : e.getSourceIp());
        out.writeLong(e.getCreatedAtMs());
    }

    public static AuditSummary readAudit(DataInputStream in) throws IOException {
        AuditSummary s = new AuditSummary();
        s.id = in.readLong();
        s.eventType = MessageIO.readString(in);
        s.username = MessageIO.readString(in);
        s.transferId = MessageIO.readString(in);
        s.outcome = MessageIO.readString(in);
        s.detail = MessageIO.readString(in);
        s.sourceIp = MessageIO.readString(in);
        s.createdAtMs = in.readLong();
        return s;
    }

    /** Client-side view of one transfer row. */
    public static final class TransferSummary {
        public String transferId;
        public String senderUsername;
        public String recipientUsername;
        public String originalFilename;
        public String contentType;
        public long plaintextSize;
        public long ciphertextSize;
        public String plaintextSha256;
        public String algorithm;
        public int keySizeBits;
        public byte[] nonce;
        public int tagBits;
        public TransferStatus status;
        public String errorDetail;
        public long createdAtMs;
        public long updatedAtMs;
    }

    /** Client-side view of one audit row. */
    public static final class AuditSummary {
        public long id;
        public String eventType;
        public String username;
        public String transferId;
        public String outcome;
        public String detail;
        public String sourceIp;
        public long createdAtMs;
    }
}
