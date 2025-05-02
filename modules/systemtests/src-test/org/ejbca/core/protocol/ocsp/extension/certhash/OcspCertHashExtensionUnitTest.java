/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp.extension.certhash;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.isismtt.ocsp.CertHash;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * Unit tests for the OchCertHashExtension class.
 * 
 * TODO: This is really a unit test, could should be moved to a unit test package when such a module is created.
 * 
 * @version $Id$
 *
 */
public class OcspCertHashExtensionUnitTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    /**
     * This test runs a vanilla run through of the process method of OcspCertHashExtension, and simply verifies that 
     * the certHash is correctly produced (i.e fingerprint by SHA256)
     * @throws CertificateException 
     * @throws OperatorCreationException 
     * 
     */
    @Test
    public void testProcess() throws NoSuchAlgorithmException, IllegalStateException, InvalidAlgorithmParameterException,
            OperatorCreationException, CertificateException {
        org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension ocspCertHashExtension = new org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension();
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate cert = CertTools.genSelfCert("CN=CertHashTest", 365, null, keys.getPrivate(), keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        Map<ASN1ObjectIdentifier,Extension> result = ocspCertHashExtension.process(null, null, null, cert, null, null);
        Extension extension = result.get(new ASN1ObjectIdentifier(org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension.CERT_HASH_OID));
        ASN1Encodable derSequence = extension.getParsedValue();
        CertHash certHash = CertHash.getInstance(derSequence);
        assertEquals("Algorithm was not extracted correctly from CertHash", org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension.SHA256, certHash.getHashAlgorithm().getAlgorithm());
        MessageDigest md = MessageDigest.getInstance("SHA256");
        String fingerprint = new String(Hex.encode(md.digest(cert.getEncoded())));
        String certificateHashAsString = new String(Hex.encode(certHash.getCertificateHash()));
        assertEquals("Fingerprint (certificate hash) was not extracted correctly", fingerprint, certificateHashAsString);
    }
}
