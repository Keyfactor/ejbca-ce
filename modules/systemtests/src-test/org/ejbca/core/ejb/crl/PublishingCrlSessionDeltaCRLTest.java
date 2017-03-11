/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests Delta CRLs.
 * 
 * @version $Id$
 */
public class PublishingCrlSessionDeltaCRLTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(PublishingCrlSessionDeltaCRLTest.class);
    
    private static final String X509CADN = "CN=" + PublishingCrlSessionDeltaCRLTest.class.getSimpleName();
    private static CA testx509ca;

    private static final String USERNAME = "deltacrltest";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private PublishingCrlSessionRemote publishingCrlSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private RevocationSessionRemote revocationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);

    private static KeyPair keys;
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrlCreateSessionCRLTest"));

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        // Set up base role that can edit roles
        setUpAuthTokenAndRole(null, PublishingCrlSessionDeltaCRLTest.class.getSimpleName(), Arrays.asList(
                StandardRules.CAADD.resource(),
                StandardRules.CAEDIT.resource(),
                StandardRules.CAREMOVE.resource(),
                StandardRules.CAACCESSBASE.resource(),
                StandardRules.CREATECRL.resource(),
                StandardRules.CREATECERT.resource()
                ), null);
        testx509ca = CaTestUtils.createTestX509CA(X509CADN, null, false);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        try {
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
        }
    }
    
    @Before
    public void setUp() throws Exception {
        // Remove any lingering testca before starting the tests
        caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
        // Now add the test CA so it is available in the tests
        caSession.addCA(alwaysAllowToken, testx509ca);
    }

    @After
    public void tearDown() throws Exception {
        // Remove any testca before exiting tests
        byte[] crl;
        while ((crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false)) != null) {
            X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
            internalCertificateStoreSession.removeCRL(alwaysAllowToken, CertTools.getFingerprintAsString(x509crl));
        }
        while ((crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true)) != null) {
            X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
            internalCertificateStoreSession.removeCRL(alwaysAllowToken, CertTools.getFingerprintAsString(x509crl));
        }

        caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
    }

    @Test
    public void testCreateNewDeltaCRL() throws Exception {
        publishingCrlSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
    
        // Get number of last Delta CRL
        int number = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        int number1 = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        assertEquals(number + 1, number1);
        byte[] crl1 = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number + 1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be
        // increased by two
        publishingCrlSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        int number2 = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        assertEquals(number1 + 2, number2);
        byte[] crl2 = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1 + 2, num2.intValue());
    }

    @Test
    public void testCheckNumberofRevokedCerts() throws Exception {
        publishingCrlSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        
        // check revoked certificates
        byte[] crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        // Get number of last CRL
        Collection<RevokedCertInfo> revfp = certificateStoreSession.listRevokedCertInfo(testx509ca.getSubjectDN(), x509crl.getThisUpdate().getTime());
        log.debug("Number of revoked certificates=" + revfp.size());
        crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);

        x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl);
        Set<? extends X509CRLEntry> revset = x509crl.getRevokedCertificates();
        int revsize = 0;
        // Revset will be null if there are no revoked certificates
        // This is probably 0
        if (revset != null) {
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        } else {
            assertEquals(0, revfp.size());
        }

        // Do some revoke
        X509Certificate cert = createCert();
        try {
            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new CRL again...
            assertTrue(publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate is present in a new CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            BigInteger num2 = CrlExtensions.getCrlNumber(x509crl);
            assertEquals(num1.intValue()+1, num2.intValue());
            revset = x509crl.getRevokedCertificates();
            assertNotNull("revset can not be null", revset);
            assertEquals(revsize + 1, revset.size());           
        } finally {
            internalCertificateStoreSession.removeCertificate(CertTools.getSerialNumber(cert));
        }
    }

    @Test
    public void testRevokeAndUnrevoke() throws Exception {
        // Test revocation and reactivation of certificates
        X509Certificate cert = createCert();

        try {
            // Create a new CRL again...
            assertTrue(publishingCrlSession.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate is not present in a new CRL
            byte[] crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
            Set<? extends X509CRLEntry> revset = x509crl.getRevokedCertificates();
            if (revset != null) {
                Iterator<? extends X509CRLEntry> iter = revset.iterator();
                while (iter.hasNext()) {
                    X509CRLEntry ce = iter.next();
                    assertTrue(ce.getSerialNumber().compareTo(cert.getSerialNumber()) != 0);
                }
            } // If no revoked certificates exist at all, this test passed...

            Thread.sleep(1000);
            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new delta CRL again...
            assertTrue(publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Delta CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull("revset can not be null", revset);
            assertTrue(isCertificatePresentInCrl(revset, cert));

            // Unrevoke the certificate that we just revoked
            // The revokeCertificate method will set the revocation date so the CRL generation code knows if it should be in the state "removeFromCRL" or not
            revocationSession.revokeCertificate(roleMgmgToken, cert, null, RevokedCertInfo.NOT_REVOKED, null);
            // Create a new Delta CRL again...
            assertTrue(publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS NOT present in the new CRL.
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            if (revset != null) {
                assertFalse(isCertificatePresentInCrl(revset, cert));
            } // If no revoked certificates exist at all, this test passed...

            // Check that when we revoke a certificate it will be present on the
            // delta CRL
            // When we create a new full CRL it will be present there, and not on
            // the next delta CRL
            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new delta CRL again...
            assertTrue(publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Delta CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull(revset);
            assertTrue(isCertificatePresentInCrl(revset, cert));

            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new Full CRL
            assertTrue(publishingCrlSession.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Full CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull(revset);
            assertTrue(isCertificatePresentInCrl(revset, cert));

            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new Delta CRL again...
            assertTrue(publishingCrlSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS NOT present in the new Delta CRL.
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            if (revset != null) {
                assertFalse(isCertificatePresentInCrl(revset, cert));
            } // If no revoked certificates exist at all, this test passed...           
        } finally {
            internalCertificateStoreSession.removeCertificate(CertTools.getSerialNumber(cert));
        }
    }

    // 
    // Helper methods
    //
    
    private boolean isCertificatePresentInCrl(final Set<? extends X509CRLEntry> revokedCertificates, final X509Certificate x509Certificate) {
        for (final X509CRLEntry ce : revokedCertificates) {
            if (ce.getSerialNumber().compareTo(x509Certificate.getSerialNumber()) == 0) {
                // TODO: verify the reason code
                return true;
            }
        }
        return false;
    }

    private X509Certificate createCert() throws Exception {
        EndEntityInformation user = new EndEntityInformation(USERNAME, "C=SE,O=AnaTom,CN=deltacrltest", testx509ca.getCAId(), null, "deltacrltest@anatom.se", new EndEntityType(EndEntityTypes.ENDUSER), 0,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        X509Certificate cert = (X509Certificate)resp.getCertificate();
        assertNotNull("Failed to create certificate", cert);
        return cert;
    }
}
