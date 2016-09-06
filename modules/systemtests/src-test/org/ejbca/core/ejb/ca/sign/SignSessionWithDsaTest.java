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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class SignSessionWithDsaTest extends SignSessionCommon {

    private static final Logger log = Logger.getLogger(SignSessionWithDsaTest.class);
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("DsaSignSessionTest"));
    private static final String DSA_USERNAME = "DsaUser";
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
        createDefaultDsaCa();
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        int caIdDsa = caSession.getCAInfo(internalAdmin, TEST_DSA_CA_NAME).getCAId();
        createEndEntity(DSA_USERNAME, SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, caIdDsa);
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
        CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        if (endEntityAccessSession.findUser(internalAdmin, DSA_USERNAME) != null) {
            endEntityManagementSession.deleteUser(internalAdmin, DSA_USERNAME);
        }        
        removeTestCA(TEST_DSA_CA_NAME);
        //Clean up certificates associated with this test class:
        for (Certificate certificate : EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(DSA_USERNAME))) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
        for(Certificate certificate : certificateStoreSession.findCertificatesBySubject("CN=TESTDSA")) {
            internalCertificateStoreSession.removeCertificate(certificate);
        }
    }
    
    @Test
    public void testSignSessionDSAWithDSACA() throws Exception {
        log.trace(">test25SignSessionDSAWithDSACA()");
        endEntityManagementSession.setUserStatus(internalAdmin, DSA_USERNAME, EndEntityConstants.STATUS_NEW, 0);
        log.debug("Reset status of '"+DSA_USERNAME+"' to NEW");
        // user that we know exists...
        KeyPair dsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_DSA);
        X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, dsakeys.getPrivate(), dsakeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_DSA, false);
        X509Certificate cert = (X509Certificate) signSession.createCertificate(internalAdmin, DSA_USERNAME, "foo123", selfcert);
        assertNotNull("Failed to create cert", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey dsapk = (DSAPublicKey) pk;
            assertEquals(dsapk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        X509Certificate dsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_DSA_CA_NAME).getCertificateChain().toArray()[0];
        try {
            cert.verify(dsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }

        log.trace("<test25SignSessionDSAWithDSACA()");
    }

    /**
     * tests bouncy PKCS10
     * 
     * @throws Exception
     *             if en error occurs...
     */
    @Test
    public void testBCPKCS10DSAWithDSACA() throws Exception {
        log.trace(">test26TestBCPKCS10DSAWithDSACA()");
        endEntityManagementSession.setUserStatus(internalAdmin, DSA_USERNAME, EndEntityConstants.STATUS_NEW, 0);
        log.debug("Reset status of 'foodsa' to NEW");
        KeyPair dsakeys = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_DSA);
        // Create certificate request
        PKCS10CertificationRequest req = CertTools.genPKCS10CertificationRequest("SHA1WithDSA", CertTools.stringToBcX500Name("C=SE, O=AnaTom, CN=foodsa"), dsakeys
                .getPublic(), new DERSet(), dsakeys.getPrivate(), null);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req.toASN1Structure());
        dOut.close();
        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
        ContentVerifierProvider verifier = CertTools.genContentVerifierProvider(dsakeys.getPublic());
        boolean verify = req2.isSignatureValid(verifier);
        log.debug("Verify returned " + verify);
        assertTrue(verify);
        log.debug("CertificationRequest generated successfully.");
        byte[] bcp10 = bOut.toByteArray();
        PKCS10RequestMessage p10 = new PKCS10RequestMessage(bcp10);
        p10.setUsername(DSA_USERNAME);
        p10.setPassword("foo123");
        ResponseMessage resp = signSession.createCertificate(internalAdmin, p10, X509ResponseMessage.class, null);
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        assertNotNull("Failed to create certificate", cert);
        log.debug("Cert=" + cert.toString());
        PublicKey pk = cert.getPublicKey();
        if (pk instanceof DSAPublicKey) {
            DSAPublicKey dsapk = (DSAPublicKey) pk;
            assertEquals(dsapk.getAlgorithm(), "DSA");
        } else {
            assertTrue("Public key is not DSA", false);
        }
        X509Certificate dsacacert = (X509Certificate) caSession.getCAInfo(internalAdmin, TEST_DSA_CA_NAME).getCertificateChain().toArray()[0];
        try {
            cert.verify(dsacacert.getPublicKey());
        } catch (Exception e) {
            assertTrue("Verify failed: " + e.getMessage(), false);
        }
        log.trace("<test26TestBCPKCS10DSAWithDSACA()");
    }
    
    @Override
    public String getRoleName() {
        return SignSessionWithDsaTest.class.getSimpleName();
    }
}
