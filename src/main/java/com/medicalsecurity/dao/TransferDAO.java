package com.medicalsecurity.dao;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferStatus;

import java.sql.SQLException;
import java.util.List;

/**
 * Transfer-metadata persistence. Status changes go through the state machine
 * in {@link TransferStatus#canTransitionTo(TransferStatus)} and use optimistic
 * locking ({@code WHERE status = ?}) so concurrent/duplicated commands cannot
 * double-count or fake success.
 */
public interface TransferDAO {

    /** Inserts a new transfer row (usually in status PENDING or ENCRYPTING). */
    long insert(ImageTransfer transfer) throws SQLException;

    ImageTransfer findByTransferId(String transferId) throws SQLException;

    List<ImageTransfer> findByRecipientId(long recipientId) throws SQLException;

    List<ImageTransfer> findBySenderId(long senderId) throws SQLException;

    List<ImageTransfer> findRecent(int limit) throws SQLException;

    /**
     * Validates the transition and updates the status atomically.
     *
     * @return true when exactly one row changed
     */
    boolean updateStatus(String transferId, TransferStatus next, String errorDetail) throws SQLException;

    /** Records storage location of the ciphertext and moves to RECEIVED. */
    boolean markReceived(String transferId, String storageRef, long ciphertextSize) throws SQLException;

    /** Stamps the completion time of a decrypted transfer. */
    boolean markCompleted(String transferId) throws SQLException;
}
