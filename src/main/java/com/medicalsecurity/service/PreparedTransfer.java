package com.medicalsecurity.service;

import com.medicalsecurity.model.TransferManifest;

import java.util.Arrays;

/**
 * Everything produced on the SENDER side for one transfer: the manifest, the
 * recipient-wrapped DEK and the ciphertext. Contains no plaintext key: the
 * DEK exists only transiently while this object is created and is then wiped.
 */
public final class PreparedTransfer {

    private final TransferManifest manifest;
    private final byte[] wrappedKey;
    private final byte[] ciphertext;
    private final byte[] originalImage;

    PreparedTransfer(TransferManifest manifest, byte[] wrappedKey, byte[] ciphertext, byte[] originalImage) {
        this.manifest = manifest;
        this.wrappedKey = java.util.Arrays.copyOf(wrappedKey, wrappedKey.length);
        this.ciphertext = java.util.Arrays.copyOf(ciphertext, ciphertext.length);
        this.originalImage = originalImage;
    }

    public TransferManifest getManifest() {
        return manifest;
    }

    public byte[] getWrappedKey() {
        return java.util.Arrays.copyOf(wrappedKey, wrappedKey.length);
    }

    public byte[] getCiphertext() {
        return java.util.Arrays.copyOf(ciphertext, ciphertext.length);
    }

    /** Original bytes (kept locally for preview/verification; never sent). */
    public byte[] getOriginalImage() {
        return originalImage == null ? null : java.util.Arrays.copyOf(originalImage, originalImage.length);
    }

    /** True when the stored ciphertext is definitely not a viewable copy. */
    public boolean ciphertextDiffersFromOriginal() {
        return !Arrays.equals(ciphertext, originalImage);
    }
}
