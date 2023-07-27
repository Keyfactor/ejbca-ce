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
package org.cesecore.keys.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.certificate.cvc.CvCertificateUtility;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCProvider;
import org.ejbca.cvc.CVCPublicKey;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.CertificateImplementationRegistry;
import com.keyfactor.util.certificate.x509.X509CertificateUtility;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 *
 */
public class CvcKeyToolsTest {

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new CvCertificateUtility());
        CertificateImplementationRegistry.INSTANCE.addCertificateImplementation(new X509CertificateUtility());
        Security.addProvider(new CVCProvider());     
    }
    
    @Test
    public void testGenKeysECDSAx9() throws Exception {
        KeyPair keys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        // Verify that the keys are using maned curves, and not explicit parameters
        PrivateKeyInfo priv2 = PrivateKeyInfo.getInstance(keys.getPrivate().getEncoded());
        assertTrue("Private key is not encoded with named curves, but using explicit parameters", X962Parameters.getInstance(priv2.getPrivateKeyAlgorithm().getParameters()).isNamedCurve());
        SubjectPublicKeyInfo pub2 = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        assertTrue("Public key is not encoded with named curves, but using explicit parameters", X962Parameters.getInstance(pub2.getAlgorithm().getParameters()).isNamedCurve());

        assertNotNull("keys must not be null", keys);
        String b64private = new String(Base64.encode(keys.getPrivate().getEncoded()));
        assertNotNull("b64private must not be null", b64private);
        // log.debug(b64private);
        X509Certificate cert = CertTools.genSelfCert("C=SE,O=Test,CN=Test", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, true);
        // log.debug(cert);
        assertNotNull("cert must not be null", cert);
        String b64cert = new String(Base64.encode(cert.getEncoded()));
        assertNotNull("b64cert cannot be null", b64cert);
        // log.debug(b64cert);
        KeyTools.testKey(keys.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
        // Test that fails
        KeyPair keys1 = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        try {
            KeyTools.testKey(keys1.getPrivate(), keys.getPublic(), BouncyCastleProvider.PROVIDER_NAME);
            assertTrue(false);
        } catch (InvalidKeyException e) {
            assertEquals("Signature was not correctly verified.", e.getMessage());
        }

        // This will not do anything for a key which is not an org.ejbca.cvc.PublicKeyEC
        PublicKey pk = CvcKeyTools.getECPublicKeyWithParams(keys.getPublic(), "prime192v1");
        assertTrue(pk.equals(keys.getPublic()));
        pk = CvcKeyTools.getECPublicKeyWithParams(keys.getPublic(), pk);
        assertTrue(pk.equals(keys.getPublic()));
        
        AlgorithmParameterSpec spec = KeyTools.getKeyGenSpec(keys.getPublic());
        assertNotNull(spec);
        assertTrue((spec instanceof ECParameterSpec));
        
        assertTrue(KeyTools.isPrivateKeyExtractable(keys.getPrivate()));
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (PrintStream ps = new PrintStream(out)) {
            KeyTools.printPublicKeyInfo(keys.getPublic(), ps);
        }
        String str = out.toString();
        assertTrue(str.contains("Elliptic curve key"));
    }
    
    @Test
    public void testGetECDSACvcPubKeyParams() throws Exception {
        // Test to enrich an EC public key that does not contain domain parameters 
        // with domain parameters from either another EC public key or from the curve name
        
        // A CVCA certificate will contain the complete ECC params 
        CVCertificate cert1 = createCVTestCertificate(AuthorizationRoleEnum.CVCA);
        CVCPublicKey pk1 = cert1.getCertificateBody().getPublicKey();

        // An IS certificate will not contain the complete ECC params 
        CVCertificate cert2 = createCVTestCertificate(AuthorizationRoleEnum.IS);
        CVCPublicKey pk2 = cert2.getCertificateBody().getPublicKey();

        ECPublicKey ecpk1 = (ECPublicKey)pk1;
        ECPublicKey ecpk2 = (ECPublicKey)pk2;
        ECParameterSpec spec1 = ecpk1.getParams();
        assertNotNull(spec1);
        ECParameterSpec spec2 = ecpk2.getParams();
        assertNull(spec2); // no parameters in IS cert
        ECPublicKey ecpk3 = (ECPublicKey)CvcKeyTools.getECPublicKeyWithParams(pk2, pk1);
        ECParameterSpec spec3 = ecpk3.getParams();
        assertNotNull(spec3);
        
        spec2 = ecpk2.getParams();
        assertNull(spec2); // no parameters in IS cert
        ECPublicKey ecpk4 = (ECPublicKey)CvcKeyTools.getECPublicKeyWithParams(ecpk2, "prime192v1");
        ECParameterSpec spec4 = ecpk4.getParams();
        assertNotNull(spec4);

        // Trying to enrich with another public key with no params will give no params in enriched key
        ECPublicKey ecpk5 = (ECPublicKey)CvcKeyTools.getECPublicKeyWithParams(ecpk2, ecpk2);
        ECParameterSpec spec5 = ecpk5.getParams();
        assertNull(spec5);

    }
    
    // Helper method to create a test CV certificate
    private CVCertificate createCVTestCertificate(AuthorizationRoleEnum role) throws Exception {
        KeyPair keyPair = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
        CAReferenceField caRef = new CAReferenceField("SE", "TEST001", "00001");
        HolderReferenceField holderRef = new HolderReferenceField("SE", "TEST002", "SE001");
        // Call method in CertificateGenerator
        return CertificateGenerator.createTestCertificate(keyPair.getPublic(), keyPair.getPrivate(), caRef, holderRef, "SHA1WithECDSA", role);
    }

}
