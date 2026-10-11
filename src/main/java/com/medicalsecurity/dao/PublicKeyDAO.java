package com.medicalsecurity.dao;

import java.sql.SQLException;

/**
 * Persistence for user PUBLIC key metadata (X.509 SubjectPublicKeyInfo DER).
 * Private keys are never stored here - they stay in PKCS#12 keystores.
 */
public interface PublicKeyDAO {

    long insert(long userId, String algorithm, int keySizeBits, byte[] publicKeyDer,
                int keyVersion, String keystoreRef) throws SQLException;

    PublicKeyRecord findLatestByUserId(long userId) throws SQLException;

    PublicKeyRecord findLatestByUsername(String username) throws SQLException;
}
