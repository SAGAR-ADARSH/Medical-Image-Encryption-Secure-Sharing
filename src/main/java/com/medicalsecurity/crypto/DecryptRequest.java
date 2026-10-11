package com.medicalsecurity.crypto;

import javax.crypto.SecretKey;

/**
 * Typed request for {@link CryptoEngine#decryptImage(DecryptRequest)}.
 */
public final class DecryptRequest {

    private final SecretKey dataKey;
    private final EncryptedPayload payload;
    private final byte[] additionalAuthenticatedData;

    public DecryptRequest(SecretKey dataKey, EncryptedPayload payload,
                          byte[] additionalAuthenticatedData) {
        if (dataKey == null) {
            throw new IllegalArgumentException("dataKey must not be null");
        }
        if (payload == null) {
            throw new IllegalArgumentException("payload must not be null");
        }
        this.dataKey = dataKey;
        this.payload = payload;
        this.additionalAuthenticatedData =
                additionalAuthenticatedData == null ? null : java.util.Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
    }

    public SecretKey getDataKey() {
        return dataKey;
    }

    public EncryptedPayload getPayload() {
        return payload;
    }

    public byte[] getAdditionalAuthenticatedData() {
        return additionalAuthenticatedData == null ? null : java.util.Arrays.copyOf(additionalAuthenticatedData, additionalAuthenticatedData.length);
    }
}
