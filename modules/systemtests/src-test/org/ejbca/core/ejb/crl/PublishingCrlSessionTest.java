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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
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
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Tests CRL create session.
 * 
 * @version $Id$
 */
public class PublishingCrlSessionTest extends RoleUsingTestCase {

    private final static Logger log = Logger.getLogger(PublishingCrlSessionTest.class);

    private static final String X509CADN = "CN=" + PublishingCrlSessionTest.class.getSimpleName();
    private static CA testx509ca;

    private static final String USERNAME = "crltest";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);

    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private PublishingCrlSessionRemote publishingCrlSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(PublishingCrlSessionRemote.class);
    private PublishingCrlProxySessionRemote publishingCrlProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            PublishingCrlProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CrlCreateSessionCRLTest"));
    
    private static KeyPair keys;

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        // Set up base role that can edit roles
        setUpAuthTokenAndRole(null, PublishingCrlSessionTest.class.getSimpleName(), Arrays.asList(
                StandardRules.CAADD.resource(),
                StandardRules.CAEDIT.resource(),
                StandardRules.CAREMOVE.resource(),
                StandardRules.CAACCESSBASE.resource(),
                StandardRules.CREATECRL.resource(),
                StandardRules.CREATECERT.resource(),
                StandardRules.CERTIFICATEPROFILEEDIT.resource()
                ), null);
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
        // Now add the test CA so it is available in the tests
        testx509ca = CaTestUtils.createTestX509CA(X509CADN, null, false);
        // Remove any lingering testca before starting the tests
        caSession.removeCA(alwaysAllowToken, X509CADN.hashCode());
        // Now add the test CA so it is available in the tests
        caSession.addCA(alwaysAllowToken, testx509ca);
    }

    @After
    public void tearDown() throws Exception {
        // Remove any testca before exiting tests
        CaTestUtils.removeCa(alwaysAllowToken, testx509ca.getCAInfo());
    }

    /**
     * creates new crl
     */
    @Test
    public void testCreateNewCRL() throws Exception {
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        X509CRL x509crl = null;

        // Get number of last CRL
        int number = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = getLastCrl(testx509ca.getSubjectDN(), false);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);

        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        // Create a new CRL again to see that the number increases
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        int number1 = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
        assertEquals(number + 1, number1);
        byte[] crl1 = getLastCrl(testx509ca.getSubjectDN(), false);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(num.intValue() + 1, num1.intValue());

        /*
         * check revoked certificates
         */

        // Get number of last CRL
        Collection<RevokedCertInfo> revfp = certificateStoreSession.listRevokedCertInfo(testx509ca.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, -1);
        log.debug("Number of revoked certificates=" + revfp.size());
        crl = getLastCrl(testx509ca.getSubjectDN(), false);
        assertNotNull("Could not get CRL", crl);

        x509crl = CertTools.getCRLfromByteArray(crl);
        Set<? extends X509CRLEntry> revset = x509crl.getRevokedCertificates();
        // Revset will be null if there are no revoked certificates
        if (revset != null) {
            int revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        } else {
            assertEquals(0, revfp.size());
        }
    }

    /**
     * Tests how expired certificates behave on the CRL
     */
    @Test
    public void testCRLWithExpiry() throws Exception {
        // Create a certificate profile where we can decide what validity we will have
        CertificateProfile certProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certProfile.setAllowValidityOverride(true);
        int profileId = certificateProfileSession.addCertificateProfile(roleMgmgToken, PublishingCrlSessionTest.class.getSimpleName(), certProfile);

        String fp = null;
        try {
            // Set the CA to keep expired certificates on the CRL
            X509CAInfo info = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, testx509ca.getCAId());
            info.setKeepExpiredCertsOnCRL(true);
            caSession.editCA(alwaysAllowToken, info);

            // Generate a certificate that is expired from the get go
            EndEntityInformation user = new EndEntityInformation(USERNAME, "C=SE,O=AnaTom,CN=crltest", testx509ca.getCAId(), null, "crltest@anatom.se",
                    new EndEntityType(EndEntityTypes.ENDUSER), 0, profileId, EndEntityConstants.TOKEN_USERGEN, null);
            SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword(), new Date(
                    System.currentTimeMillis()));
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams());
            X509Certificate cert = (X509Certificate) resp.getCertificate();
            fp = CertTools.getFingerprintAsString(cert);
            //Wait two seconds to make sure the certificate is expired
            Thread.sleep(2000);
            assertTrue("Certificate should be expired, but is not. notAfter: "+cert.getNotAfter()+", now: "+new Date(), cert.getNotAfter().before(new Date()));

            // Create a CRL verify that our expired, but unrevoked certificate is not on it
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            byte[] crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
            assertFalse("Certificate should not be present on the CRL", x509crl.isRevoked(cert));
            // Revoke it, it shall now be on the CRL
            internalCertificateStoreSession.setRevokeStatus(alwaysAllowToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED);
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            assertTrue("Certificate should be present on the CRL", x509crl.isRevoked(cert));
            // And two more times, to make sure it doesn't disappear, since we use keepExpiredCertsOnCRL
            info = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, testx509ca.getCAId());
            assertTrue(info.getKeepExpiredCertsOnCRL());
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            final BigInteger initialCrlNumber = CrlExtensions.getCrlNumber(x509crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            assertFalse("Forced CRL generation did nothing.", CrlExtensions.getCrlNumber(x509crl).equals(initialCrlNumber));
            assertTrue("Certificate should be present on the CRL", x509crl.isRevoked(cert));
            // Also verify that the ExpiredCertsOnCRL CRL extension is on this CRL
            Set<String> extensions = x509crl.getNonCriticalExtensionOIDs();
            assertTrue("CRL does not contain the ExpiredCertsOnCRL extension, even though KeepExpiredCertsOnCRL is set to true", extensions.contains("2.5.29.60"));
            
            // Change to not keep expired certificates on CRL
            info = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, testx509ca.getCAId());
            info.setKeepExpiredCertsOnCRL(false);
            caSession.editCA(alwaysAllowToken, info);
            // It should be in the first, because it is now that status is set to archived to it will not appear on the next CRL
            CertificateInfo certInfo = certificateStoreSession.getCertificateInfo(fp);
            assertEquals("Info should be REVOKED before generating CRL that will set it to ARCHIVED", CertificateConstants.CERT_REVOKED, certInfo.getStatus());
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            assertTrue("Certificate should be present on the CRL", x509crl.isRevoked(cert));
            certInfo = certificateStoreSession.getCertificateInfo(fp);
            assertEquals("Info should be ARCHIVED after generating CRL", CertificateConstants.CERT_ARCHIVED, certInfo.getStatus());
            // Second time it should be gone
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            assertFalse("Certificate should not be present on the CRL", x509crl.isRevoked(cert));
            // Also verify that the ExpiredCertsOnCRL CRL extension is not on this CRL
            extensions = x509crl.getNonCriticalExtensionOIDs();
            assertFalse("CRL contains the ExpiredCertsOnCRL extension, even though KeepExpiredCertsOnCRL is set to false", extensions.contains("2.5.29.60"));
        } finally {
            // Remove certificate profile we created here
            certificateProfileSession.removeCertificateProfile(alwaysAllowToken, PublishingCrlSessionTest.class.getSimpleName());
            // Remove generated certificate
            internalCertificateStoreSession.removeCertificate(fp);
            // Set back default value for keep expired certificates on CRL
            X509CAInfo info = (X509CAInfo) caSession.getCAInfo(alwaysAllowToken, testx509ca.getCAId());
            info.setKeepExpiredCertsOnCRL(false);
            caSession.editCA(alwaysAllowToken, info);
        }
    }

    /**
     * Test revocation and reactivation of certificates
     * 
     */
    @Test
    public void testRevokeAndUnrevoke() throws Exception {

        X509Certificate cert = createCert();
        try {
            // Create a new CRL again...
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate is not present in a new CRL
            byte[] crl = getLastCrl(testx509ca.getSubjectDN(), false);
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

            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            // Create a new CRL again...
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new CRL
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull(revset);
            assertTrue("Certificate with serial " + cert.getSerialNumber().toString(16) + " not revoked", isCertificatePresentInCrl(revset, cert));

            // Unrevoke the certificate that we just revoked
            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.NOT_REVOKED);
            // Create a new CRL again...
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS NOT present in the new
            // CRL.
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            if (revset != null) {
                assertFalse(isCertificatePresentInCrl(revset, cert));
            } // If no revoked certificates exist at all, this test passed...

            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE);
            assertTrue("Failed to revoke certificate!",
                    certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert)));
            // Create a new CRL again...
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new CRL
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertTrue(isCertificatePresentInCrl(revset, cert));

            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.NOT_REVOKED);
            assertTrue("Was able to re-activate permanently revoked certificate!",
                    certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert)));
            // Create a new CRL again...
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate is present in the new CRL,
            // because the revocation reason
            // was not CERTIFICATE_HOLD, we can only un-revoke certificates that are
            // on hold.
            crl = getLastCrl(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertTrue(isCertificatePresentInCrl(revset, cert));
        } finally {
            internalCertificateStoreSession.removeCertificate(cert);
        }

    }

    /**
     * Test Overflow of CRL Period
     */
    @Test
    public void testCRLPeriodOverflow() throws Exception {
        log.trace(">test05CRLPeriodOverflow()");
        // Fetch CAInfo and save CRLPeriod
        CAInfo cainfo = testx509ca.getCAInfo();
        long tempCRLPeriod = cainfo.getCRLPeriod();
        X509Certificate cert = createCert();
        try {
            // Revoke the user
            internalCertificateStoreSession.setRevokeStatus(roleMgmgToken, cert, new Date(), RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE);
            // Change CRLPeriod
            cainfo.setCRLPeriod(Long.MAX_VALUE);
            caSession.editCA(roleMgmgToken, cainfo);
            // Create new CRL's
            assertTrue(publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Verify that status is not archived
            CertificateInfo certinfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
            assertFalse("Non Expired Revoked Certificate was archived", certinfo.getStatus() == CertificateConstants.CERT_ARCHIVED);
        } finally {
            internalCertificateStoreSession.removeCertificate(CertTools.getSerialNumber(cert));
            // Restore CRL Period
            cainfo.setCRLPeriod(tempCRLPeriod);
            caSession.editCA(roleMgmgToken, cainfo);
        }
    }

    /**
     * Tests the extension CRL Distribution Point on CRLs
     */
    @Test
    public void testCRLDistPointOnCRL() throws Exception {
        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
        X509CRL x509crl;
        byte[] cdpDER;

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        caSession.editCA(roleMgmgToken, cainfo);
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        x509crl = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
        cdpDER = x509crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
        assertNotNull("CRL has no distribution points", cdpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cdpDER));
        final ASN1OctetString octs = ASN1OctetString.getInstance(aIn.readObject());
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        final IssuingDistributionPoint cdp = IssuingDistributionPoint.getInstance(aIn.readObject());
        final DistributionPointName distpoint = cdp.getDistributionPoint();

        assertEquals("CRL distribution point is different", cdpURL,
                ((DERIA5String) ((GeneralNames) distpoint.getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint("");
        caSession.editCA(roleMgmgToken, cainfo);
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        x509crl = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
        assertNull("CRL has distribution points", x509crl.getExtensionValue(Extension.cRLDistributionPoints.getId()));
    }

    /**
     * Tests the extension Freshest CRL DP.
     */
    @Test
    public void testCRLFreshestCRL() throws Exception {
        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        final String freshestCdpURL = "http://www.ejbca.org/foo/delta.crl";
        X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
        X509CRL x509crl;
        byte[] cFreshestDpDER;

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        cainfo.setCADefinedFreshestCRL(freshestCdpURL);
        caSession.editCA(roleMgmgToken, cainfo);
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        x509crl = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
        cFreshestDpDER = x509crl.getExtensionValue(Extension.freshestCRL.getId());
        assertNotNull("CRL has no Freshest Distribution Point", cFreshestDpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cFreshestDpDER));
        ASN1OctetString octs = ASN1OctetString.getInstance(aIn.readObject());
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        CRLDistPoint cdp = CRLDistPoint.getInstance(aIn.readObject());
        DistributionPoint[] distpoints = cdp.getDistributionPoints();

        assertEquals("More CRL Freshest distributions points than expected", 1, distpoints.length);
        assertEquals("Freshest CRL distribution point is different", freshestCdpURL, ((DERIA5String) ((GeneralNames) distpoints[0]
                .getDistributionPoint().getName()).getNames()[0].getName()).getString());
    }

    @Test
    public void testCrlGenerateForAll() throws Exception {
        X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
        cainfo.setCRLIssueInterval(1); // Issue very often..
        cainfo.setDeltaCRLPeriod(1); // Issue very often..
        caSession.editCA(roleMgmgToken, cainfo);
        // make sure we have a CRL and delta CRL generated
        publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
        publishingCrlSessionRemote.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        try {
            // Now wait and test again
            Thread.sleep(1000);
            final X509CRL x509crl = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
            assertTrue(publishingCrlSessionRemote.createCRLs(roleMgmgToken).size() > 0);
            final X509CRL x509crlAfter = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
            assertTrue("Did not generate a newer CRL.", x509crlAfter.getThisUpdate().after(x509crl.getThisUpdate()));
            final X509CRL x509deltaCrl = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), true));
            assertTrue(publishingCrlSessionRemote.createDeltaCRLs(roleMgmgToken).size() > 0);
            final X509CRL x509deltaCrlAfter = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), true));
            assertTrue("Did not generate a newer Delta CRL.", x509deltaCrlAfter.getThisUpdate().after(x509deltaCrl.getThisUpdate()));
            // Try a similar thing when we specify which CA IDs to generate CRLs for
            // Compare CRL numbers instead of Dates, since these CRLs might have been generated the same second as the last ones
            final Collection<Integer> caids = new ArrayList<>();
            caids.add(Integer.valueOf(testx509ca.getCAId()));
            publishingCrlProxySession.createCRLs(roleMgmgToken, caids, 2);
            final X509CRL x509crlAfter2 = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), false));
            assertTrue("Did not generate a newer CRL.",
                    CrlExtensions.getCrlNumber(x509crlAfter2).intValue() > CrlExtensions.getCrlNumber(x509crlAfter).intValue());
            publishingCrlProxySession.createDeltaCRLs(roleMgmgToken, caids, 2);
            final X509CRL x509deltaCrlAfter2 = CertTools.getCRLfromByteArray(getLastCrl(cainfo.getSubjectDN(), true));
            assertTrue("Did not generate a newer Delta CRL.",
                    CrlExtensions.getCrlNumber(x509deltaCrlAfter2).intValue() > CrlExtensions.getCrlNumber(x509deltaCrlAfter).intValue());
        } finally {
            byte[] crl;
            while ((crl = getLastCrl(testx509ca.getSubjectDN(), false)) != null) {
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                internalCertificateStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(x509crl));
            }
            while ((crl = getLastCrl(testx509ca.getSubjectDN(), true)) != null) {
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                internalCertificateStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(x509crl));
            }
        }
    }

    /**
     * Test error handling of off-line CA during CRL creation.
     */
    @Test
    public void testCrlCreateSessionErrorHandling() throws Exception {
        CAInfo cainfo = testx509ca.getCAInfo();
        cainfo.setStatus(CAConstants.CA_OFFLINE);
        caSession.editCA(roleMgmgToken, cainfo);
        CA ca = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        assertEquals(CAConstants.CA_OFFLINE, ca.getStatus());
        assertEquals(CAConstants.CA_OFFLINE, ca.getCAInfo().getStatus());
        try {
            publishingCrlSessionRemote.forceCRL(roleMgmgToken, testx509ca.getCAId());
            assertTrue("Trying to generate a CRL for CA with status CA_OFFLINE did not throw the CATokenOfflineException.", false);
        } catch (CAOfflineException e) {
            // Expected
        }
        cainfo.setStatus(CAConstants.CA_ACTIVE);
        caSession.editCA(roleMgmgToken, cainfo);
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
        EndEntityInformation user = new EndEntityInformation(USERNAME, "C=SE,O=AnaTom,CN=crltest", testx509ca.getCAId(), null, "crltest@anatom.se",
                new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, null);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
        X509Certificate cert = (X509Certificate)resp.getCertificate();
        assertNotNull("Failed to create certificate", cert);
        return cert;
    }

    private byte[] getLastCrl(final String issuerDn, final boolean deltaCrl) {
        return crlStoreSession.getLastCRL(issuerDn, CertificateConstants.NO_CRL_PARTITION, deltaCrl);
    }
}
