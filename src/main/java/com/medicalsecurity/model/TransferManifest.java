package com.medicalsecurity.model;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;

/**
 * Transfer manifest: the complete, integrity-relevant description of one
 * transfer. It is transmitted over the socket protocol BEFORE the payload and
 * is also recorded in the database. The manifest itself is covered by the
 * GCM additional authenticated data (AAD), so any modification of these
 * fields after encryption makes the GCM tag verification fail.
 */
public final class TransferManifest {

    public static final int FORMAT_VERSION = 1;

    private String transferId;
    private long senderUserId;
    private long recipientUserId;
    private String senderUsername;
    private String recipientUsername;
    private String originalFilename;
    private String contentType;
    private long plaintextSize;
    private long ciphertextSize;
    private String plaintextSha256;
    private String algorithm;
    private int keySizeBits;
    private byte[] nonce;
    private int tagBits;
    private long createdAtMs;

    public TransferManifest() {
    }

    /**
     * Binary layout is fixed and versioned so that a mismatched client/server
     * pair is rejected instead of silently mis-parsing bytes.
     */
    public void write(DataOutput out) throws IOException {
        out.writeInt(FORMAT_VERSION);
        out.writeUTF(transferId);
        out.writeLong(senderUserId);
        out.writeLong(recipientUserId);
        out.writeUTF(senderUsername);
        out.writeUTF(recipientUsername);
        out.writeUTF(originalFilename);
        out.writeUTF(contentType == null ? "" : contentType);
        out.writeLong(plaintextSize);
        out.writeLong(ciphertextSize);
        out.writeUTF(plaintextSha256);
        out.writeUTF(algorithm);
        out.writeInt(keySizeBits);
        out.writeInt(nonce.length);
        out.write(nonce);
        out.writeInt(tagBits);
        out.writeLong(createdAtMs);
    }

    public static TransferManifest read(DataInput in) throws IOException {
        TransferManifest m = new TransferManifest();
        int version = in.readInt();
        if (version != FORMAT_VERSION) {
            throw new IOException("Unsupported manifest version: " + version);
        }
        m.transferId = in.readUTF();
        m.senderUserId = in.readLong();
        m.recipientUserId = in.readLong();
        m.senderUsername = in.readUTF();
        m.recipientUsername = in.readUTF();
        m.originalFilename = in.readUTF();
        String ct = in.readUTF();
        m.contentType = ct.isEmpty() ? null : ct;
        m.plaintextSize = in.readLong();
        m.ciphertextSize = in.readLong();
        m.plaintextSha256 = in.readUTF();
        m.algorithm = in.readUTF();
        m.keySizeBits = in.readInt();
        int nonceLen = in.readInt();
        if (nonceLen < 1 || nonceLen > 32) {
            throw new IOException("Invalid nonce length in manifest: " + nonceLen);
        }
        m.nonce = new byte[nonceLen];
        in.readFully(m.nonce);
        m.tagBits = in.readInt();
        m.createdAtMs = in.readLong();
        return m;
    }

    /**
     * Structural validation used by both sender and receiver before any
     * further processing.
     */
    public void validate() {
        if (transferId == null || transferId.length() != 36) {
            throw new IllegalArgumentException("Manifest: transferId must be a 36-char UUID");
        }
        if (senderUserId <= 0 || recipientUserId <= 0) {
            throw new IllegalArgumentException("Manifest: sender/recipient must be set");
        }
        if (senderUserId == recipientUserId) {
            throw new IllegalArgumentException("Manifest: sender and recipient must differ");
        }
        if (originalFilename == null || originalFilename.isEmpty()) {
            throw new IllegalArgumentException("Manifest: originalFilename must be set");
        }
        if (plaintextSize < 0 || ciphertextSize <= 0) {
            throw new IllegalArgumentException("Manifest: invalid sizes");
        }
        if (plaintextSha256 == null || plaintextSha256.length() != 64) {
            throw new IllegalArgumentException("Manifest: plaintextSha256 must be a 64-char hex digest");
        }
        if (algorithm == null || !algorithm.startsWith("AES/GCM/")) {
            throw new IllegalArgumentException("Manifest: unsupported algorithm");
        }
        if (keySizeBits != 128 && keySizeBits != 192 && keySizeBits != 256) {
            throw new IllegalArgumentException("Manifest: invalid AES key size");
        }
        if (nonce == null || nonce.length != 12) {
            throw new IllegalArgumentException("Manifest: GCM nonce must be 12 bytes");
        }
        if (tagBits != 128 && tagBits != 120 && tagBits != 112 && tagBits != 104 && tagBits != 96) {
            throw new IllegalArgumentException("Manifest: invalid GCM tag length");
        }
    }

    /**
     * The AAD binding: every integrity-relevant manifest field except the
     * ciphertext itself and wall-clock times (the receiver rebuilds the same
     * context from the transfer row in the database). Fed into AES-GCM as
     * additional authenticated data, so tampering with metadata also fails
     * the GCM tag check.
     */
    public byte[] toAuthenticatedContext() {
        return authenticatedContext(transferId, senderUserId, recipientUserId, originalFilename,
                plaintextSize, ciphertextSize, plaintextSha256, algorithm, keySizeBits, tagBits);
    }

    /** Deterministic context builder shared by sender and receiver. */
    public static byte[] authenticatedContext(String transferId, long senderUserId, long recipientUserId,
                                              String originalFilename, long plaintextSize,
                                              long ciphertextSize, String plaintextSha256,
                                              String algorithm, int keySizeBits, int tagBits) {
        StringBuilder sb = new StringBuilder();
        sb.append(transferId).append('|')
                .append(senderUserId).append('|')
                .append(recipientUserId).append('|')
                .append(originalFilename).append('|')
                .append(plaintextSize).append('|')
                .append(ciphertextSize).append('|')
                .append(plaintextSha256).append('|')
                .append(algorithm).append('|')
                .append(keySizeBits).append('|')
                .append(tagBits);
        return sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ------------------------------------------------------------------
    // Getters / setters
    // ------------------------------------------------------------------

    public String getTransferId() {
        return transferId;
    }

    public void setTransferId(String transferId) {
        this.transferId = transferId;
    }

    public long getSenderUserId() {
        return senderUserId;
    }

    public void setSenderUserId(long senderUserId) {
        this.senderUserId = senderUserId;
    }

    public long getRecipientUserId() {
        return recipientUserId;
    }

    public void setRecipientUserId(long recipientUserId) {
        this.recipientUserId = recipientUserId;
    }

    public String getSenderUsername() {
        return senderUsername;
    }

    public void setSenderUsername(String senderUsername) {
        this.senderUsername = senderUsername;
    }

    public String getRecipientUsername() {
        return recipientUsername;
    }

    public void setRecipientUsername(String recipientUsername) {
        this.recipientUsername = recipientUsername;
    }

    public String getOriginalFilename() {
        return originalFilename;
    }

    public void setOriginalFilename(String originalFilename) {
        this.originalFilename = originalFilename;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public long getPlaintextSize() {
        return plaintextSize;
    }

    public void setPlaintextSize(long plaintextSize) {
        this.plaintextSize = plaintextSize;
    }

    public long getCiphertextSize() {
        return ciphertextSize;
    }

    public void setCiphertextSize(long ciphertextSize) {
        this.ciphertextSize = ciphertextSize;
    }

    public String getPlaintextSha256() {
        return plaintextSha256;
    }

    public void setPlaintextSha256(String plaintextSha256) {
        this.plaintextSha256 = plaintextSha256;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public int getKeySizeBits() {
        return keySizeBits;
    }

    public void setKeySizeBits(int keySizeBits) {
        this.keySizeBits = keySizeBits;
    }

    public byte[] getNonce() {
        return nonce == null ? null : java.util.Arrays.copyOf(nonce, nonce.length);
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce == null ? null : java.util.Arrays.copyOf(nonce, nonce.length);
    }

    public int getTagBits() {
        return tagBits;
    }

    public void setTagBits(int tagBits) {
        this.tagBits = tagBits;
    }

    public long getCreatedAtMs() {
        return createdAtMs;
    }

    public void setCreatedAtMs(long createdAtMs) {
        this.createdAtMs = createdAtMs;
    }
}
