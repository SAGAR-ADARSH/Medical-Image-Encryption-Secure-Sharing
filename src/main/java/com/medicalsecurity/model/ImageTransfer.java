package com.medicalsecurity.model;

import java.util.Arrays;

/**
 * Database entity for one image transfer. The ciphertext itself lives in the
 * secure storage directory; this object carries only metadata.
 */
public final class ImageTransfer {

    private long id;
    private String transferId;
    private long senderId;
    private long recipientId;
    private String originalFilename;
    private String contentType;
    private long plaintextSize;
    private long ciphertextSize;
    private String plaintextSha256;
    private String algorithm;
    private int keySizeBits;
    private byte[] nonce;
    private int tagBits;
    private TransferStatus status;
    private String storageRef;
    private String errorDetail;
    private long createdAtMs;
    private long updatedAtMs;
    private Long receivedAtMs;
    private Long completedAtMs;

    public ImageTransfer() {
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTransferId() {
        return transferId;
    }

    public void setTransferId(String transferId) {
        this.transferId = transferId;
    }

    public long getSenderId() {
        return senderId;
    }

    public void setSenderId(long senderId) {
        this.senderId = senderId;
    }

    public long getRecipientId() {
        return recipientId;
    }

    public void setRecipientId(long recipientId) {
        this.recipientId = recipientId;
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
        return nonce == null ? null : Arrays.copyOf(nonce, nonce.length);
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce == null ? null : Arrays.copyOf(nonce, nonce.length);
    }

    public int getTagBits() {
        return tagBits;
    }

    public void setTagBits(int tagBits) {
        this.tagBits = tagBits;
    }

    public TransferStatus getStatus() {
        return status;
    }

    public void setStatus(TransferStatus status) {
        this.status = status;
    }

    public String getStorageRef() {
        return storageRef;
    }

    public void setStorageRef(String storageRef) {
        this.storageRef = storageRef;
    }

    public String getErrorDetail() {
        return errorDetail;
    }

    public void setErrorDetail(String errorDetail) {
        this.errorDetail = errorDetail;
    }

    public long getCreatedAtMs() {
        return createdAtMs;
    }

    public void setCreatedAtMs(long createdAtMs) {
        this.createdAtMs = createdAtMs;
    }

    public long getUpdatedAtMs() {
        return updatedAtMs;
    }

    public void setUpdatedAtMs(long updatedAtMs) {
        this.updatedAtMs = updatedAtMs;
    }

    public Long getReceivedAtMs() {
        return receivedAtMs;
    }

    public void setReceivedAtMs(Long receivedAtMs) {
        this.receivedAtMs = receivedAtMs;
    }

    public Long getCompletedAtMs() {
        return completedAtMs;
    }

    public void setCompletedAtMs(Long completedAtMs) {
        this.completedAtMs = completedAtMs;
    }
}
