package com.medicalsecurity.dao;

/**
 * One public-key record of a user (current key version). Public keys are not
 * secret; private keys are never part of this record.
 */
public final class PublicKeyRecord {

    public final long id;
    public final long userId;
    public final String username;
    public final String algorithm;
    public final int keySizeBits;
    public final byte[] publicKeyDer;
    public final int keyVersion;

    public PublicKeyRecord(long id, long userId, String username, String algorithm,
                           int keySizeBits, byte[] publicKeyDer, int keyVersion) {
        this.id = id;
        this.userId = userId;
        this.username = username;
        this.algorithm = algorithm;
        this.keySizeBits = keySizeBits;
        this.publicKeyDer = publicKeyDer;
        this.keyVersion = keyVersion;
    }
}
