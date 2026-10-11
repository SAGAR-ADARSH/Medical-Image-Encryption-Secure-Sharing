package com.medicalsecurity.crypto;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Minimal, standards-compliant X.509 v3 self-signed certificate generator.
 *
 * <p>Why: PKCS#12 keystores require a certificate chain for every private-key
 * entry. This class produces a conventional self-signed certificate (CN = the
 * username) so key pairs can be provisioned fully IN-PROCESS with the standard
 * JCE + KeyStore APIs - no external tools, no custom cryptography (the
 * signature is plain SHA256withRSA via JCE; only the documented ASN.1/DER
 * structure of X.509 is encoded here).
 *
 * <p>The certificate is used as a public-key container for the keystore; the
 * project does not build a PKI and does not treat these certificates as a
 * trust hierarchy.
 */
final class SelfSignedCertificate {

    private SelfSignedCertificate() {
    }

    static X509Certificate create(String commonName, PublicKey publicKey, PrivateKey privateKey,
                                  int validityDays) throws GeneralSecurityException {
        try {
            byte[] tbs = tbsCertificate(commonName, publicKey, validityDays);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(privateKey, com.medicalsecurity.util.SecureIds.secureRandom());
            signer.update(tbs);
            byte[] signature = signer.sign();

            byte[] certDer = der(0x30, concat(tbs, der(0x30, concat(oid(new int[]{1, 2, 840, 113549, 1, 1, 11}),
                    der(0x05, new byte[0]))), der(0x03, concat(new byte[]{0x00}, signature))));
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certDer));
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException("Certificate generation failed", e);
        }
    }

    // ------------------------------------------------------------------
    // TBSCertificate
    // ------------------------------------------------------------------

    private static byte[] tbsCertificate(String commonName, PublicKey publicKey, int validityDays)
            throws java.io.IOException {
        long now = System.currentTimeMillis();
        Date notBefore = new Date(now - 60L * 60L * 1000L); // clock-skew tolerance
        Date notAfter = new Date(now + validityDays * 24L * 60L * 60L * 1000L);

        byte[] version = der(0xA0, der(0x02, new byte[]{0x02})); // v3
        byte[] serial = der(0x02, positiveInteger(BigInteger.valueOf(now ^ 0x5A5A5A5AL)));
        byte[] sigAlg = der(0x30, concat(oid(new int[]{1, 2, 840, 113549, 1, 1, 11}), der(0x05, new byte[0])));
        byte[] issuer = name(commonName);
        byte[] validity = der(0x30, concat(utcTime(notBefore), utcTime(notAfter)));
        byte[] subject = name(commonName);
        byte[] spki = publicKey.getEncoded(); // already DER SubjectPublicKeyInfo

        return der(0x30, concat(version, serial, sigAlg, issuer, validity, subject, spki));
    }

    /** Name ::= SEQUENCE OF RelativeDistinguishedName (CN, OU, O). */
    private static byte[] name(String commonName) throws java.io.IOException {
        byte[] cn = der(0x31, der(0x30, concat(oid(new int[]{2, 5, 4, 3}), printableString(commonName))));
        byte[] ou = der(0x31, der(0x30, concat(oid(new int[]{2, 5, 4, 11}), printableString("MedicalImageSecurity"))));
        byte[] org = der(0x31, der(0x30, concat(oid(new int[]{2, 5, 4, 10}), printableString("AcademicDemo"))));
        return der(0x30, concat(cn, ou, org));
    }

    // ------------------------------------------------------------------
    // Primitive DER encoders
    // ------------------------------------------------------------------

    private static byte[] der(int tag, byte[] content) throws java.io.IOException {
        return concat(new byte[]{(byte) tag}, derLength(content.length), content);
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[]{(byte) length};
        }
        if (length <= 0xFF) {
            return new byte[]{(byte) 0x81, (byte) length};
        }
        return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
    }

    /** INTEGER from a non-negative BigInteger (minimal encoding, 0x00 pad). */
    private static byte[] positiveInteger(BigInteger value) throws java.io.IOException {
        byte[] bytes = value.toByteArray();
        return der(0x02, bytes);
    }

    /** OBJECT IDENTIFIER from its arc numbers. */
    private static byte[] oid(int[] arcs) throws java.io.IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write(arcs[0] * 40 + arcs[1]);
        for (int i = 2; i < arcs.length; i++) {
            writeBase128(out, arcs[i]);
        }
        return der(0x06, out.toByteArray());
    }

    private static void writeBase128(java.io.ByteArrayOutputStream out, int value) {
        int count = 1;
        int tmp = value;
        while (tmp > 127) {
            tmp = tmp >>> 7;
            count = count + 1;
        }
        for (int i = count - 1; i >= 0; i--) {
            int shift = 7 * i;
            int b = (value >>> shift) & 0x7F;
            if (i != 0) {
                b = b | 0x80;
            }
            out.write(b);
        }
    }

    /** UTCTime "YYMMDDHHMMSSZ". */
    private static byte[] utcTime(Date date) throws java.io.IOException {
        java.text.SimpleDateFormat format = new java.text.SimpleDateFormat("yyMMddHHmmss'Z'");
        format.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        byte[] text = format.format(date).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return der(0x17, text);
    }

    /** PrintableString (subset sufficient for usernames and org names). */
    private static byte[] printableString(String value) throws java.io.IOException {
        byte[] text = value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return der(0x13, text);
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (int i = 0; i < parts.length; i++) {
            total += parts[i].length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (int i = 0; i < parts.length; i++) {
            System.arraycopy(parts[i], 0, out, offset, parts[i].length);
            offset += parts[i].length;
        }
        return out;
    }
}
