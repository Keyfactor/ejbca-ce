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
package org.ejbca.ssh.keys.ec;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;

/**
 * @version $Id$
 *
 */
public class SshEcPublicKey implements SshPublicKey {
    public static final String ENCODING_ALGORITHM_BASE = "ecdsa-sha2-";
    public static final String NISTP256 = "nistp256";
    public static final String NISTP384 = "nistp384";
    public static final String NISTP521 = "nistp521";
    public static final String SECP256R1 = "secp256r1";
    public static final String SECP384R1 = "secp384r1";
    public static final String SECP521R1 = "secp521r1";
    public static final String PRIME256V1 = "prime256v1";
    public static final String PRIME384V1 = "prime384v1";
    public static final String PRIME521V1 = "prime521v1";
    
    private static final List<String> keyAlgorithms = Arrays.asList("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521");
    
    private static final long serialVersionUID = 1L;

    private ECPublicKey ecPublicKey;
    private String curveName;

    /**
     * Required by service locator
     */
    public SshEcPublicKey() {
        ecPublicKey = null;
        curveName = null;
    }

    public SshEcPublicKey(final ECPublicKey ecPublicKey) throws InvalidKeySpecException {
        this.ecPublicKey = ecPublicKey;
        this.curveName = getSshCurveNameFromPublicKey(ecPublicKey);
    }

    /**
     * Read an RSA public key encoded in SSH format
     * 
     * @param encodedBytes a byte array containing the public key, in the format: <br>
     * @throws SshKeyException if the key was not an EC key, or the encoded array could not be read. 
     * @throws InvalidKeySpecException if the key specification was incorrect
     */
    public SshEcPublicKey(final byte[] encodedBytes) throws SshKeyException, InvalidKeySpecException {
        init(encodedBytes);
    }
    
    @Override
    public void init(byte[] keyBody) throws SshKeyException, InvalidKeySpecException {
        SshCertificateReader sshCertificateReader = new SshCertificateReader(keyBody);

        try {
            String algorithm = sshCertificateReader.readString();
            if (!algorithm.startsWith(ENCODING_ALGORITHM_BASE)) {
                throw new SshKeyException("Endoded key was not prefixed with " + ENCODING_ALGORITHM_BASE + ", was " + algorithm + ".");
            }
            this.curveName = sshCertificateReader.readString();
            String curve = translateCurveName(curveName);
            ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(AlgorithmTools.getEcKeySpecOidFromBcName(curve));
            EllipticCurve ellipticCurve = EC5Util.convertCurve(ecParameterSpec.getCurve(), ecParameterSpec.getSeed());
            byte[] encodedPoint = sshCertificateReader.readByteArray();
            ECPoint ecPoint = KeyTools.decodeEcPoint(encodedPoint, ellipticCurve);
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_EC);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(AlgorithmConstants.KEYALGORITHM_EC + " was not a valid algorithm.", e);
            }
            this.ecPublicKey = (ECPublicKey) keyFactory
                    .generatePublic(new ECPublicKeySpec(ecPoint, EC5Util.convertSpec(ellipticCurve, ecParameterSpec)));
        } catch (IOException e) {
            throw new SshKeyException("Could not read encoded key.", e);
        } finally {
            sshCertificateReader.close();
        }
        
    }

    /**
     * The nistp* curves are not widely known in crypto libraries - translate the curve name into a more known one. 
     * 
     * @param curve the original curve name
     * @return the converted curve name
     * @throws InvalidKeySpecException if the curve name didn't match up to nistp256, nistp384 or nistp521
     */
    public static String translateCurveName(final String curve) throws InvalidKeySpecException {
        switch (curve) {
        case NISTP256:
            return SECP256R1;
        case NISTP384:
            return SECP384R1;
        case NISTP521:
            return SECP521R1;
        default:
            throw new InvalidKeySpecException("Unkown curve of name " + curve);

        }
    }
    
    public static String getSshCurveNameFromPublicKey(ECPublicKey publicKey) throws InvalidKeySpecException {
        switch (AlgorithmTools.getKeySpecification(publicKey)) {
        case SECP256R1:
        case PRIME256V1:
        case "1.3.132.0.prime256v1":
        case "1.2.840.10045.3.1.7":
        case "P-256":
            return NISTP256;
        case SECP384R1:
        case PRIME384V1:
        case "1.3.132.0.34":
        case "P-384":
            return NISTP384;
        case SECP521R1:
        case PRIME521V1:
        case "1.3.132.0.35":
        case "P-521":
            return NISTP521;
        default:
            throw new InvalidKeySpecException("Curve " + AlgorithmTools.getKeySpecification(publicKey) + " is not valid for SSH certificates.");
        }
    }

    private String getEncodingAlgorithm() {
        return ENCODING_ALGORITHM_BASE + curveName;
    }

    @Override
    public byte[] encode() throws IOException {
        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
            sshCertificateWriter.writeString(getEncodingAlgorithm());
            sshCertificateWriter.writeString(curveName);
            sshCertificateWriter.writeByteArray(KeyTools.encodeEcPoint(ecPublicKey.getW(), ecPublicKey.getParams().getCurve()));
        } finally {
            sshCertificateWriter.flush();
            sshCertificateWriter.close();
        }

        return sshCertificateWriter.toByteArray();
    }

    @Override
    public byte[] encodeForExport(String comment) throws IOException {
        String result = getEncodingAlgorithm() + " ";
        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
            sshCertificateWriter.writeByteArray(encode());
        } finally {
            sshCertificateWriter.flush();
            sshCertificateWriter.close();
        }
        result += new String(Base64.encode(encode(), false), StandardCharsets.UTF_8);
        if (comment != null && comment.trim().length() > 0) {
            result += " " + comment;
        }
        return result.getBytes();
    }

    @Override
    public List<String> getSshKeyAlgorithms() {
        return keyAlgorithms;
    }
    
    @Override
    public String getKeyAlgorithm() {
        return AlgorithmConstants.KEYALGORITHM_EC;
    }


    public void setEcPublicKey(ECPublicKey ecPublicKey) throws InvalidKeySpecException {
        this.ecPublicKey = ecPublicKey;
        if(curveName == null) {
            curveName = getSshCurveNameFromPublicKey(ecPublicKey);
        }
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        try {
            setEcPublicKey((ECPublicKey) publicKey);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException("Public key was not of a known SSH EC type.", e);
        }
    }

    @Override
    public PublicKey getPublicKey() {
        return ecPublicKey;
    }
    
    public String getCurveName() {
        return curveName;
    }
}
