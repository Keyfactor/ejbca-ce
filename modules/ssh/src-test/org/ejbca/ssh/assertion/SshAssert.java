/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.assertion;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.ejbca.ssh.keys.ec.SshEcPublicKey;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * A set of assertion methods useful for writing EJBCA SSH tests. Only failed assertions are thrown.
 *
 * @version $Id$
 */
public class SshAssert {

    public static Map<String, String> readCriticalOptions(final SshCertificateReader sshCertificateReader) throws IOException {
        // Critical options are enclosed in a byte structure of their own
        byte[] optionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader optionsReader = new SshCertificateReader(optionsBytes);
        Map<String, String> options = new HashMap<>();
        while (optionsReader.available() > 0) {
            final String optionName = optionsReader.readString();
            // Value will be coded as a set of Strings
            final SshCertificateReader optionReader = new SshCertificateReader(optionsReader.readByteArray());
            final String optionValue = optionReader.readString();
            optionReader.close();
            options.put(optionName, optionValue);
        }
        optionsReader.close();
        return options;
    }

    /**
     * Reads critical options from SshCertificateReader and asserts values.
     *
     * @param sshCertificateReader SSH Certificate reader.
     * @param sourceAddress Value for option SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS
     * @throws IOException IO exception.
     */
    public static void readAndVerifyCriticalOptions(final SshCertificateReader sshCertificateReader, final String sourceAddress) throws IOException {
        final Map<String, String> options = readCriticalOptions(sshCertificateReader);
        assertEquals("Incorrect critical options were read.", 1, options.size());
        assertTrue("Option was not found", options.containsKey(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS));
        assertEquals("Option value was incorrect", sourceAddress, options.get(SshCertificate.CRITICAL_OPTION_SOURCE_ADDRESS));
    }

    /**
     * Verifies the EC signature.
     *
     * @param publicKey Public key
     * @param signatureBytes Signature bytes.
     * @param signatureAlgorithm Signature algorithm.
     * @param data data.
     * @return true if EC signature is valid.
     * @throws NoSuchAlgorithmException no algorithm exception.
     * @throws SignatureException signature exception.
     * @throws InvalidKeyException invalid key exception.
     * @throws IOException IO exception.
     */
    public static boolean verifyEcSignature(
            ECPublicKey publicKey, byte[] signatureBytes, String signatureAlgorithm, byte[] data
    ) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
        Signature signature;
        switch (signatureAlgorithm) {
            case SshEcPublicKey.NISTP521:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA512_WITH_ECDSA);
                break;
            case SshEcPublicKey.NISTP384:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA384_WITH_ECDSA);
                break;
            default:
                signature = Signature.getInstance(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
                break;
        }
        // EC signature consists of two big integers encoded in a
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(byteArrayOutputStream);
        SshCertificateReader sshCertificateReader = new SshCertificateReader(signatureBytes);
        seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
        seq.addObject(new ASN1Integer(sshCertificateReader.readBigInteger()));
        sshCertificateReader.close();
        seq.close();
        byte[] encoded = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(encoded);
    }

    /**
     * Verifies the RSA signature.
     *
     * @param publicKey Public key
     * @param signatureBytes Signature bytes.
     * @param signatureAlgorithm Signature algorithm, for example AlgorithmConstants.SIGALG_SHA256_WITH_RSA.
     * @param data data.
     * @return true if RSA signature is valid.
     * @throws NoSuchAlgorithmException no algorithm exception.
     * @throws SignatureException signature exception.
     * @throws InvalidKeyException invalid key exception.
     * @throws IOException IO exception.
     */
    public static boolean verifyRsaSignature(
            RSAPublicKey publicKey, byte[] signatureBytes, String signatureAlgorithm, byte[] data
    ) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException {
        final Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

}
