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
package org.ejbca.core.ejb.ca.sign;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class SignSessionWithMfg1Test extends SignSessionCommon {

    private static final Logger log = Logger.getLogger(SignSessionWithMfg1Test.class);

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Mfg1SignSessionTest"));

    private static final String RSA_MFG1_ENTITY_NAME = "foorsamgf1ca";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

    private static KeyPair rsakeys;

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createRSASha256WithMGF1CA();
        rsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);

        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CAInfo inforsamgf1ca = caSession.getCAInfo(internalAdmin, TEST_SHA256_WITH_MFG1_CA_NAME);
        int rsamgf1cacaid = inforsamgf1ca.getCAId();

        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        if (!endEntityManagementSession.existsUser("foorsamgf1ca")) {
            endEntityManagementSession.addUser(internalAdmin, "foorsamgf1ca", "foo123", "C=SE,O=AnaTom,CN=foorsamgf1ca", null, "foo@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                    SecConst.TOKEN_SOFT_PEM, 0, rsamgf1cacaid);
            log.debug("created user: foorsamgf1ca, foo123, C=SE, O=AnaTom, CN=foorsamgf1ca");
        } else {
            log.info("User foorsamgf1ca already exists, resetting status.");
            endEntityManagementSession.setUserStatus(internalAdmin, "foorsamgf1ca", EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
    }

    @AfterClass
    public static void afterClass() throws Exception {
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        endEntityManagementSession.deleteUser(internalAdmin, RSA_MFG1_ENTITY_NAME);

        removeTestCA(TEST_SHA256_WITH_MFG1_CA_NAME);
    }

    @Test
    public void testSignSessionRSAMGF1WithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test18SignSessionRSAWithRSASha256WithMGF1CA()");
        endEntityManagementSession.setUserStatus(internalAdmin, RSA_MFG1_ENTITY_NAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of 'foorsamgf1ca' to NEW");
        // user that we know exists...
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, rsakeys.getPrivate(), rsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1, false);
        try {
            selfcert.verify(selfcert.getPublicKey());
        } catch (Exception e) {
            e.printStackTrace();
            assertTrue(false);
        }
        X509Certificate retcert = (X509Certificate) signSession.createCertificate(internalAdmin, RSA_MFG1_ENTITY_NAME, "foo123", selfcert);
        // RSA with MGF1 is not supported by sun, so we must transfer this
        // (serialized) cert to a BC cert
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(retcert.getEncoded());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            assertTrue("Public key is not RSA", false);
        }
        X509Certificate rsamgf1cacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_SHA256_WITH_MFG1_CA_NAME).getCertificateChain()
                .toArray()[0];
        try {
            cert.verify(rsamgf1cacacert.getPublicKey());
        } catch (Exception e) {
            // e.printStackTrace();
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // 1.2.840.113549.1.1.10 is SHA256WithRSAAndMGF1
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgName());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgName());
        log.trace("<test18SignSessionRSAWithRSASha256WithMGF1CA()");

    }

    /**
     * tests bouncy PKCS10
     * 
     */
    @Test
    public void testBCPKCS10RSAWithRSASha256WithMGF1CA() throws Exception {
        log.trace(">test19TestBCPKCS10RSAWithRSASha256WithMGF1CA()");
        endEntityManagementSession.setUserStatus(internalAdmin, RSA_MFG1_ENTITY_NAME, EndEntityConstants.STATUS_NEW);
        log.debug("Reset status of 'foorsamgf1ca' to NEW");
        // Create certificate request
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest(AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1,
                CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=" + RSA_MFG1_ENTITY_NAME), rsakeys.getPublic(), new DERSet(), rsakeys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();
        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(rsakeys.getPublic());
        boolean verify = req2.isSignatureValid(verifier);
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername("foorsamgf1ca");
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        X509Certificate cert = (X509Certificate) CertTools.getCertfromByteArray(resp.getResponseMessage());
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof RSAPublicKey) {
            RSAPublicKey rsapk = (RSAPublicKey) pk;
            assertEquals(rsapk.getAlgorithm(), "RSA");
        } else {
            assertTrue("Public key is not RSA", false);
        }
        X509Certificate rsamgf1cacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_SHA256_WITH_MFG1_CA_NAME).getCertificateChain()
                .toArray()[0];
        try {
            cert.verify(rsamgf1cacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        // 1.2.840.113549.1.1.10 is SHA256WithRSAAndMGF1
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", cert.getSigAlgName());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgOID());
        assertEquals("1.2.840.113549.1.1.10", rsamgf1cacacert.getSigAlgName());
        log.trace("<test19TestBCPKCS10RSAWithRSASha256WithMGF1CA()");
    }

    @Override
    public String getRoleName() {
        return SignSessionWithMfg1Test.class.getSimpleName();
    }

}
