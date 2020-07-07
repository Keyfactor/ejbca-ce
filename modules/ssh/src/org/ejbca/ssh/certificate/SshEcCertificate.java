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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;

/**
 * SSH EC Certificate.
 *
 * @version $Id$
 */
public class SshEcCertificate extends SshCertificateBase {

    public static final String SSH_EC_CERT_PREFIX = "ecdsa-sha2-";
    public static final String SSH_EC_CERT_POSTFIX = "-cert-v01@openssh.com";

    private static final Set<String> knownPrefixes = new HashSet<>(Arrays.asList(SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SSH_EC_CERT_POSTFIX,
            SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP384 + SSH_EC_CERT_POSTFIX, SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP521+ SSH_EC_CERT_POSTFIX));

    public SshEcCertificate() {
        super();
    }

    public SshEcCertificate(final SshPublicKey publicKey, byte[] nonce, final String serialNumber, final SshCertificateType sshCertificateType,
            final String keyId, final Set<String> principals, final Date validAfter, final Date validBefore,
            final Map<String, String> criticalOptions, final Map<String, byte[]> extensions, final SshPublicKey signKey, final String comment, final String issuerIdentifier) {
        super(publicKey, nonce, serialNumber, sshCertificateType, keyId, principals, validAfter, validBefore, criticalOptions, extensions, signKey, comment, issuerIdentifier);
    }

    @Override
    public void init(byte[] encodedCertificate) throws CertificateEncodingException, SshKeyException {
        String certificateString = new String(encodedCertificate);
        String[] splitCertificateString = certificateString.split(" ");
        if (!knownPrefixes.contains(splitCertificateString[0])) {
            throw new CertificateEncodingException(
                    "Certificate was of unknown type, was '" + splitCertificateString[0] + "'.");
        }
        byte[] certificateBody = Base64.decode(splitCertificateString[1].getBytes());
        try (SshCertificateReader sshCertificateReader = new SshCertificateReader(certificateBody)) {
            final String certificateAlgorithm = sshCertificateReader.readString();
            if (!knownPrefixes.contains(certificateAlgorithm)) {
                throw new CertificateEncodingException(
                        "Certificate was of unknown type, was '" + certificateAlgorithm + "'.");
            }
            setNonce(sshCertificateReader.readByteArray());
            final String curveName = sshCertificateReader.readString();
            final byte[] pointBytes = sshCertificateReader.readByteArray();
            final ECParameterSpec ecParameterSpec = ECNamedCurveTable
                    .getParameterSpec(SshEcPublicKey.translateCurveName(curveName));
            final EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
            ECPoint ecPoint = KeyTools.decodeEcPoint(pointBytes, ellipticCurve);
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_EC);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(AlgorithmConstants.KEYALGORITHM_EC + " was not a valid algorithm.", e);
            }
            ECPublicKey ecPublicKey = (ECPublicKey) keyFactory
                    .generatePublic(new ECPublicKeySpec(ecPoint, EC5Util.convertSpec(ellipticCurve, ecParameterSpec)));
            setPublicKey(new SshEcPublicKey(ecPublicKey));
            init(sshCertificateReader);
        } catch (IOException | InvalidKeySpecException e) {
            throw new CertificateEncodingException(e);
        }
    }

    @Override
    protected void getEncoded(SshCertificateWriter sshCertificateWriter) throws IOException {
        sshCertificateWriter.writeString(getCertificatePrefix());
        sshCertificateWriter.writeByteArray(getNonce());
        ECPublicKey ecPublicKey = (ECPublicKey) getPublicKey();
        sshCertificateWriter.writeString(((SshEcPublicKey) getSshPublicKey()).getCurveName());
        sshCertificateWriter.writeByteArray(KeyTools.encodeEcPoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve()));
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
        SshEcPublicKey sshEcPublicKey = (SshEcPublicKey) getSshPublicKey();
        return SSH_EC_CERT_PREFIX + sshEcPublicKey.getCurveName() + SSH_EC_CERT_POSTFIX;
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
        String result = getCertificatePrefix() + " ";
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
        // TODO ECA-9293: SSH Implement
        return null;
    }

    @Override
    protected boolean verifySignature(String signatureAlgorithm, byte[] signatureBytes, byte[] data) throws InvalidKeyException, SignatureException {
        Signature signature;
        try {
            switch (signatureAlgorithm) {
            case SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP521:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
                break;
            case SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP384:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
                break;
            case SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
                break;
            default:
                return false;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unknown algorithm was found", e);
        }
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DERSequenceGenerator seq = new DERSequenceGenerator(byteArrayOutputStream);
            SshCertificateReader sshCertificateReader = new SshCertificateReader(signatureBytes);
            seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
            seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
            sshCertificateReader.close();
            seq.close();
            byte[] encoded = byteArrayOutputStream.toByteArray();
            byteArrayOutputStream.close();
            signature.initVerify(getSigningKey().getPublicKey());
            signature.update(data);
            return signature.verify(encoded);
        } catch (IOException e) {
            throw new SignatureException("Could not parse signature.", e);
        }
    }

    @Override
    public List<String> getCertificateImplementations() {
        return Arrays.asList(SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP256 + SSH_EC_CERT_POSTFIX,
                SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP384 + SSH_EC_CERT_POSTFIX,
                SSH_EC_CERT_PREFIX + SshEcPublicKey.NISTP521 + SSH_EC_CERT_POSTFIX);
    }

}
