package com.medicalsecurity.dao;

import com.medicalsecurity.model.ProtectedKeyMaterial;

import java.sql.SQLException;

/**
 * Persistence for PROTECTED (wrapped) key material only. The schema and this
 * DAO deliberately have no column for a plaintext key.
 */
public interface KeyRecordDAO {

    void insert(ProtectedKeyMaterial material) throws SQLException;

    ProtectedKeyMaterial findByTransferId(String transferId) throws SQLException;
}
