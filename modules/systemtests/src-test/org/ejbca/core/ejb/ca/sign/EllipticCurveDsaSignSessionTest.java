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
package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class EllipticCurveDsaSignSessionTest extends SignSessionCommon {

    private static final Logger log = Logger.getLogger(EllipticCurveDsaSignSessionTest.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "EllipticCurveDsaSignSessionTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private UserAdminSessionRemote userAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserAdminSessionRemote.class);

    private static final String RSA_USERNAME = "RsaUser";
    private static final String ECDSA_USERNAME = "EcdsaUser";
    private static final String DEFAULT_EE_PROFILE = "ECDSAEEPROFILE";
    private static final String DEFAULT_CERTIFICATE_PROFILE = "ECDSACERTPROFILE";

    private static KeyPair ecdsakeys;

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();

        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        createTestCA();
        createEllipticCurveDsaCa();
        createEllipticCurveDsaImplicitCa();

        int rsacaid = caSession.getCAInfo(internalAdmin, getTestCAName()).getCAId();
        createEndEntity(RSA_USERNAME, DEFAULT_EE_PROFILE, DEFAULT_CERTIFICATE_PROFILE, rsacaid);
        createEcdsaEndEntity();
        ecdsakeys = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        UserAdminSessionRemote userAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(UserAdminSessionRemote.class);
        cleanUpEndEntity(RSA_USERNAME);
        userAdminSession.deleteUser(internalAdmin, ECDSA_USERNAME);
        removeTestCA();
        removeTestCA(TEST_ECDSA_CA_NAME);
        removeTestCA(TEST_ECDSA_IMPLICIT_CA_NAME);
    }

    @Test
    public void testSignSessionECDSAWithRSACA() throws Exception {
        log.trace(">test12SignSessionECDSAWithRSACA()");
        userAdminSession.setUserStatus(internalAdmin, RSA_USERNAME, UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, RSA_USERNAME, "foo123", selfcert);
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            X509Certificate rsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, getTestCAName()).getCertificateChain().toArray()[0];
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test12SignSessionECDSAWithRSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     */
    @Test
    public void testBCPKCS10ECDSAWithRSACA() throws Exception {
        log.trace(">test13TestBCPKCS10ECDSAWithRSACA()");

        userAdminSession.setUserStatus(internalAdmin, RSA_USERNAME, UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN=foo"),
                ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername(RSA_USERNAME);
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            X509Certificate rsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, getTestCAName()).getCertificateChain().toArray()[0];
            cert.verify(rsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test13TestBCPKCS10ECDSAWithRSACA()");
    }

    @Test
    public void testSignSessionECDSAWithECDSACA() throws Exception {
        log.trace(">test14SignSessionECDSAWithECDSACA()");
        userAdminSession.setUserStatus(internalAdmin, ECDSA_USERNAME, UserDataConstants.STATUS_NEW);
        log.debug("Reset status of '" + ECDSA_USERNAME + "' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, ECDSA_USERNAME, "foo123", selfcert);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        X509Certificate ecdsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME).getCertificateChain().toArray()[0];
        try {
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test14SignSessionECDSAWithECDSACA()");
    }

    /**
     * tests bouncy PKCS10
     */
    @Test
    public void testBCPKCS10ECDSAWithECDSACA() throws Exception {
        log.trace(">test15TestBCPKCS10ECDSAWithECDSACA()");

        userAdminSession.setUserStatus(internalAdmin, ECDSA_USERNAME, UserDataConstants.STATUS_NEW);
        log.debug("Reset status of 'foo' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN="
                + ECDSA_USERNAME), ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate());
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        boolean verify = req2.verify();
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername(ECDSA_USERNAME);
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof JCEECPublicKey) {
            JCEECPublicKey ecpk = (JCEECPublicKey) pk;
            assertEquals(ecpk.getAlgorithm(), "EC");
            org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
            assertNotNull("ImplicitlyCA must have null spec", spec);
        } else {
            assertTrue("Public key is not EC", false);
        }
        try {
            X509Certificate ecdsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME).getCertificateChain().toArray()[0];
            cert.verify(ecdsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test15TestBCPKCS10ECDSAWithECDSACA()");
    }

    @Test
    public void testSignSessionECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test16SignSessionECDSAWithECDSAImplicitlyCACA()");
        final String ecDsaImplicitCaUserName = "fooecdsaimpca";
        CAInfo infoecdsaimplicitlyca = caSession.getCAInfo(internalAdmin, TEST_ECDSA_IMPLICIT_CA_NAME);
        int ecdsaimplicitlycacaid = infoecdsaimplicitlyca.getCAId();
        createEndEntity(ecDsaImplicitCaUserName, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                ecdsaimplicitlycacaid);
        try {
            userAdminSession.setUserStatus(internalAdmin, ecDsaImplicitCaUserName, UserDataConstants.STATUS_NEW);
            log.debug("Reset status of 'fooecdsaimpca' to NEW");
            // user that we know exists...
            X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, ecdsakeys.getPrivate(), ecdsakeys.getPublic(),
                    AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, false);
            X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, ecDsaImplicitCaUserName, "foo123", selfcert);
            assertNotNull("Misslyckades skapa cert", cert);
            log.debug("Cert=" + cert.toString());
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
                JCEECPublicKey ecpk = (JCEECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
                assertNotNull("ImplicitlyCA must have null spec", spec);
            } else {
                fail("Public key is not EC");
            }
            X509Certificate ecdsaimplicitlycacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_IMPLICIT_CA_NAME)
                    .getCertificateChain().toArray()[0];
            try {
                cert.verify(ecdsaimplicitlycacacert.getPublicKey());
            } catch (Exception e) {
                fail("Verify failed: " + e.getMessage());
            }
        } finally {
            userAdminSession.deleteUser(internalAdmin, ecDsaImplicitCaUserName);
        }
        log.trace("<test16SignSessionECDSAWithECDSAImplicitlyCACA()");
    }

    @Test
    public void testBCPKCS10ECDSAWithECDSAImplicitlyCACA() throws Exception {
        log.trace(">test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA()");
        final String ecDsaImplicitCaUserName = "fooecdsaimpca";
        CAInfo infoecdsaimplicitlyca = caSession.getCAInfo(internalAdmin, TEST_ECDSA_IMPLICIT_CA_NAME);
        int ecdsaimplicitlycacaid = infoecdsaimplicitlyca.getCAId();
        createEndEntity(ecDsaImplicitCaUserName, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                ecdsaimplicitlycacaid);
        try {
            userAdminSession.setUserStatus(internalAdmin, ecDsaImplicitCaUserName, UserDataConstants.STATUS_NEW);
            log.debug("Reset status of 'foo' to NEW");
            // Create certificate request
            PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA256WithECDSA", CertTools.stringToBcX509Name("C=SE, O=AnaTom, CN="
                    + ecDsaImplicitCaUserName), ecdsakeys.getPublic(), new DERSet(), ecdsakeys.getPrivate());
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            DEROutputStream dOut = new DEROutputStream(bOut);
            dOut.writeObject(req);
            dOut.close();
            PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
            boolean verify = req2.verify();
            log.debug("Verify returned " + verify);
            assertTrue(verify);
            log.debug("CertificationRequest generated successfully.");
            byte[] bcp10 = bOut.toByteArray();
            PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
            p10.setUsername(ecDsaImplicitCaUserName);
            p10.setPassword("foo123");
            ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
            Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage());
            assertNotNull("Failed to create certificate", cert);
            log.debug("Cert=" + cert.toString());
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
                JCEECPublicKey ecpk = (JCEECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
                assertNotNull("ImplicitlyCA must have null spec", spec);
            } else {
                assertTrue("Public key is not EC", false);
            }
            X509Certificate ecdsaimplicitlycacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_ECDSA_IMPLICIT_CA_NAME)
                    .getCertificateChain().toArray()[0];
            try {
                cert.verify(ecdsaimplicitlycacacert.getPublicKey());
            } catch (Exception e) {
                assertTrue("Verify failed: " + e.getMessage(), false);
            }
        } finally {
            userAdminSession.deleteUser(internalAdmin, ecDsaImplicitCaUserName);
        }
        log.trace("<test17TestBCPKCS10ECDSAWithECDSAImplicitlyCACA()");
    }

    @Test
    public void testCVCertificateEccKeys() throws Exception {
        createDefaultCvcEccCaDomestic();
        final String eccUsername = "cvcec";

        CAInfo infocvccaec = caSession.getCAInfo(internalAdmin, "TESTDVECC-D");
        int cvccaecid = infocvccaec.getCAId();
        // Same thing but with ECC keys
        EndEntityInformation userec = new EndEntityInformation(eccUsername, "C=SE,CN=TCVCEC", cvccaecid, null, null, new EndEntityType(EndEntityTypes.ENDUSER),
                SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        userec.setPassword("cvc");
        userAdminSession.addUser(internalAdmin, userec, false);
        userAdminSession.setUserStatus(internalAdmin, eccUsername, UserDataConstants.STATUS_NEW);
        userAdminSession.setPassword(internalAdmin, eccUsername, "foo123");
        try {
            log.debug("Reset status of 'cvcec' to NEW");
            // user that we know exists...
            KeyPair ecdsasecpkeys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
            Certificate certec = (Certificate) signSession.createCertificate(internalAdmin, eccUsername, "foo123", ecdsasecpkeys.getPublic());
            assertNotNull("Failed to create cert", certec);
            log.debug("Cert=" + certec.toString());
            // Normal DN order
            assertEquals(CertTools.getSubjectDN(certec), "CN=TCVCEC,C=SE");
            assertEquals("CVC", certec.getType());
            Certificate cvcdveccert = (Certificate) infocvccaec.getCertificateChain().toArray()[0];
            Certificate cvcaeccert = (Certificate) infocvccaec.getCertificateChain().toArray()[1];
            assertEquals(CertTools.getIssuerDN(certec), CertTools.getSubjectDN(cvcdveccert));
            try {
                // Here we need the CVCA certificate as well to enrich the DV public
                // key with
                PublicKey pkec = cvcdveccert.getPublicKey();
                pkec = KeyTools.getECPublicKeyWithParams(pkec, cvcaeccert.getPublicKey());
                certec.verify(pkec);
            } catch (Exception e) {
                assertTrue("Verify failed: " + e.getMessage(), false);
            }
            CardVerifiableCertificate cvcert = (CardVerifiableCertificate) certec;
            String role = cvcert.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField().getRole().name();
            assertEquals("IS", role);
            PublicKey pk = cvcert.getPublicKey();
            if (pk instanceof ECPublicKey) {
                ECPublicKey epk = (ECPublicKey) pk;
                assertEquals(epk.getAlgorithm(), "ECDSA");
                int len = KeyTools.getKeyLength(epk);
                assertEquals(0, len); // the DVCA does not include all EC parameters
                // in the public key, so we don't know the key
                // length
            } else {
                assertTrue("Public key is not ECC", false);
            }
        } finally {
            removeTestCA(TEST_CVC_ECC_DOCUMENT_VERIFIER_NAME);
            removeTestCA(TEST_CVC_ECC_CA_NAME);
            userAdminSession.deleteUser(internalAdmin, eccUsername);
        }

        log.trace("<test21CVCertificate()");
    }

    @Override
    public String getRoleName() {
        return EllipticCurveDsaSignSessionTest.class.getSimpleName();
    }

    private static void createEcdsaEndEntity() throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo infoecdsa = caSession.getCAInfo(internalAdmin, TEST_ECDSA_CA_NAME);
        assertTrue("No active ECDSA CA! Must have at least one active CA to run tests!", infoecdsa != null);
        createEndEntity(ECDSA_USERNAME, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, infoecdsa.getCAId());
    }

}
