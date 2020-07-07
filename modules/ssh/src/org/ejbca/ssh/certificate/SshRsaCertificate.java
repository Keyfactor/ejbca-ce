/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;
import org.ejbca.ssh.keys.rsa.SshRsaPublicKey;

/**
 * SSH RSA Certificate.
 *
 * @version $Id$
 */
public class SshRsaCertificate extends SshCertificateBase {

    private static final Logger log = Logger.getLogger(SshRsaCertificate.class);

    private static final String SSH_RSA_CERT_V01 = "ssh-rsa-cert-v01@openssh.com";

    public SshRsaCertificate() {
        super();
    }

    public SshRsaCertificate(final SshPublicKey publicKey, byte[] nonce, final String serialNumber, final SshCertificateType sshCertificateType,
            final String keyId, final Set<String> principals, final Date validAfter, final Date validBefore, final Map<String, String> criticalOptions,
            final Map<String, byte[]> extensions, final SshPublicKey signKey, final String comment, final String issuerIdentifier) {
        super(publicKey, nonce, serialNumber, sshCertificateType, keyId, principals, validAfter, validBefore, criticalOptions, extensions, signKey, comment, issuerIdentifier);
    }

    @Override
    public void init(byte[] encodedCertificate) throws CertificateEncodingException, SshKeyException {
        String certificateString = new String(encodedCertificate);
        String[] splitCertificateString = certificateString.split(" ");
        if (!splitCertificateString[0].equals(SSH_RSA_CERT_V01)) {
            throw new CertificateEncodingException(
                    "Certificate was not of type '" + SSH_RSA_CERT_V01 + "', was '" + splitCertificateString[0] + "'.");
        }
        byte[] certificateBody = Base64.decode(splitCertificateString[1].getBytes());
        try (SshCertificateReader sshCertificateReader = new SshCertificateReader(certificateBody)) {
            String algorithm = sshCertificateReader.readString();
            if (!algorithm.equals(SSH_RSA_CERT_V01)) {
                throw new SshKeyException("Endoded key was not prefixed with " + SSH_RSA_CERT_V01 + ", was " + algorithm + ".");
            }
            setNonce(sshCertificateReader.readByteArray());
            BigInteger exponent = sshCertificateReader.readBigInteger();
            BigInteger modulus = sshCertificateReader.readBigInteger();
            setPublicKey(new SshRsaPublicKey(modulus, exponent));
            init(sshCertificateReader);
        } catch (IOException | InvalidKeySpecException e) {
            throw new CertificateEncodingException(e);
        }
    }

    @Override
    protected void getEncoded(SshCertificateWriter sshCertificateWriter) throws IOException {
        sshCertificateWriter.writeString(getCertificatePrefix());
        sshCertificateWriter.writeByteArray(getNonce());
        sshCertificateWriter.writeBigInteger(((RSAPublicKey) getPublicKey()).getPublicExponent());
        sshCertificateWriter.writeBigInteger(((RSAPublicKey) getPublicKey()).getModulus());
        super.getEncoded(sshCertificateWriter);
    }

    @Override
    public byte[] encodeCertificateBody() throws CertificateEncodingException {
        try {
            SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
            try {
                getEncoded(sshCertificateWriter);
            } finally {
                sshCertificateWriter.flush();
                sshCertificateWriter.close();
            }
            return sshCertificateWriter.toByteArray();
        } catch (IOException e) {
            throw new CertificateEncodingException(e);
        }
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        return encodeForExport();
    }

   @Override
   public String getCertificatePrefix() {
       return SSH_RSA_CERT_V01;
   }

    /**
     * Encodes this certificate for export to the standard SSH certificate format
     *
     * @return a byte array containing the encoded certificate
     * @throws CertificateEncodingException if this method was run on a pre-cert (without the signature set), or any encoding error happened
     */
    public byte[] encodeForExport() throws CertificateEncodingException {
        if (getSignature() == null) {
            throw new CertificateEncodingException("Signature has not been set, this is still a pre-cert.");
        }
        String result = SSH_RSA_CERT_V01 + " ";
        try {
            SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
            try {
                getEncoded(sshCertificateWriter);
                sshCertificateWriter.writeByteArray(getSignature());
            } finally {
                sshCertificateWriter.flush();
                sshCertificateWriter.close();
            }
            result += new String(Base64.encode(sshCertificateWriter.toByteArray(), false), StandardCharsets.UTF_8);
            if (getComment() != null && getComment().trim().length() > 0) {
                result += " " + getComment();
            }
            return result.getBytes();
        } catch (IOException e) {
            throw new CertificateEncodingException(e);
        }
    }

    @Override
    public String toString() {
        //TODO SSH: Implement ECA-9184
        return null;
    }

    @Override
    protected boolean verifySignature(String signatureAlgorithm, byte[] signatureBytes, byte[] data) throws InvalidKeyException, SignatureException {
        Signature signature;
        try {
            switch (signatureAlgorithm) {
            case SshRsaPublicKey.SSH_RSA2_SHA512:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA512_WITH_RSA);
                break;
            case SshRsaPublicKey.SSH_RSA2_SHA256:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
                break;
            case SshRsaPublicKey.SSH_RSA:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
                break;
            default:
                return false;
            }
            return verifySignature(signature, signatureBytes, data, true);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown algorithm was found", e);
        }
    }

    private boolean verifySignature(final Signature signature, byte[] signatureBytes, byte[] data, boolean allowCorrect)
            throws SignatureException, InvalidKeyException {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) getSigningKey().getPublicKey();
        signature.initVerify(rsaPublicKey);
        signature.update(data);
        int expectedLength = getSignatureLength(rsaPublicKey.getModulus());
        boolean corrected = false;
        byte[] original = signatureBytes;
        if(log.isDebugEnabled()) {
            log.debug("Signing payload of size: " + data.length);
            log.debug("Signature: " + signature.toString());

        }
        if (signatureBytes.length < expectedLength) {
            if (log.isDebugEnabled()) {
                log.debug("No Padding Detected: Expected signature length of " + expectedLength + " (modulus=" + rsaPublicKey.getModulus().bitLength()
                        + ") but got " + signatureBytes.length);
            }
            byte[] tmp = new byte[expectedLength];
            System.arraycopy(signature, 0, tmp, expectedLength - signatureBytes.length, signatureBytes.length);
            signatureBytes = tmp;
            corrected = true;
        }
        boolean result = false;
        try {
            if(log.isDebugEnabled() ) {
                log.debug("Signature length: " + signatureBytes.length);
            }
            result = signature.verify(signatureBytes);
        } catch (SignatureException e) {
            if (!allowCorrect) {
                throw e;
            }
            if (log.isDebugEnabled()) {
                log.debug("Signature failed. Falling back to raw signature data.");
            }
        }

        if (!result) {
            if (corrected) {
                result = verifySignature(signature, original, data, false);
            }
        }
        return result;
    }

    /**
     *
     * @param modulus the modulus of an RSA key
     * @return the expected signature length
     */
    private int getSignatureLength(BigInteger modulus) {
        int length = modulus.bitLength() / 8;
        int mod = modulus.bitLength() % 8;
        if (mod != 0) {
            length++;
        }
        return length;
    }

    @Override
    public List<String> getCertificateImplementations() {
        return Collections.singletonList(SSH_RSA_CERT_V01);
    }

}
