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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests Delta CRLs.
 * 
 * Based on EJBCA version: DeltaCRLTest.java 11010 2010-12-29 17:40:11Z jeklund
 * 
 * @version $Id$
 */
public class CrlCreateSessionDeltaCRLTest extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(CrlCreateSessionDeltaCRLTest.class);
    
    private static final String X509CADN = "CN=TEST";
    private static CA testx509ca;

	private static final String USERNAME = "deltacrltest";

    private CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = JndiHelper.getRemoteSession(CertificateStoreSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = JndiHelper.getRemoteSession(CrlStoreSessionRemote.class);
    private CrlCreateSessionRemote crlCreateSession = JndiHelper.getRemoteSession(CrlCreateSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = JndiHelper.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    private static KeyPair keys;
    
    @BeforeClass
    public static void createProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        testx509ca = CaSessionTest.createTestX509CA(X509CADN, null, false);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }
    
    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("DeltaCrlCreateSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("DeltaCrlCreateSessionTest");

        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECRL.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        // Remove any lingering testca before starting the tests
        caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
        // Now add the test CA so it is available in the tests
        caSession.addCA(roleMgmgToken, testx509ca);

    }

    @After
    public void tearDown() throws Exception {
        // Remove any testca before exiting tests
        try {
            byte[] crl;
            while ((crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false)) != null) {
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                internalCertificateStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(x509crl));
            }
            while ((crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true)) != null) {
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                internalCertificateStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(x509crl));
            }

            caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
        }
    }

    @Test
    public void testCreateNewDeltaCRL() throws Exception {
        crlCreateSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
    
        // Get number of last Delta CRL
        int number = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        int number1 = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        assertEquals(number + 1, number1);
        byte[] crl1 = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number + 1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be
        // increased by two
        crlCreateSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        int number2 = crlStoreSession.getLastCRLNumber(testx509ca.getSubjectDN(), true);
        assertEquals(number1 + 2, number2);
        byte[] crl2 = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1 + 2, num2.intValue());
    }

    @Test
    public void testCheckNumberofRevokedCerts() throws Exception {
        crlCreateSession.forceCRL(roleMgmgToken, testx509ca.getCAId());
        crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId());
        
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
            certificateStoreSession.setRevokeStatus(roleMgmgToken, cert, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, null);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new CRL again...
            assertTrue(crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
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
            assertTrue(crlCreateSession.forceCRL(roleMgmgToken, testx509ca.getCAId()));
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

            certificateStoreSession.setRevokeStatus(roleMgmgToken, cert, RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, null);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new delta CRL again...
            assertTrue(crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Delta CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull("revset can not be null", revset);
            Iterator<? extends X509CRLEntry> iter = revset.iterator();
            boolean found = false;
            while (iter.hasNext()) {
                X509CRLEntry ce = iter.next();
                if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
                    found = true;
                    // TODO: verify the reason code
                }
            }
            assertTrue(found);

            // Unrevoke the certificate that we just revoked
            certificateStoreSession.setRevokeStatus(roleMgmgToken, cert, RevokedCertInfo.NOT_REVOKED, null);
            // Create a new Delta CRL again...
            assertTrue(crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS NOT present in the new CRL.
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            if (revset != null) {
                iter = revset.iterator();
                found = false;
                while (iter.hasNext()) {
                    X509CRLEntry ce = (X509CRLEntry) iter.next();
                    if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
                        found = true;
                    }
                }
                assertFalse(found);
            } // If no revoked certificates exist at all, this test passed...

            // Check that when we revoke a certificate it will be present on the
            // delta CRL
            // When we create a new full CRL it will be present there, and not on
            // the next delta CRL
            certificateStoreSession.setRevokeStatus(roleMgmgToken, cert, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, null);
            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new delta CRL again...
            assertTrue(crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Delta CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull(revset);
            iter = revset.iterator();
            found = false;
            // log.debug(x509crl.getThisUpdate());
            while (iter.hasNext()) {
                X509CRLEntry ce = (X509CRLEntry) iter.next();
                // log.debug(ce);
                if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
                    found = true;
                    // TODO: verify the reason code
                }
            }
            assertTrue(found);

            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new Full CRL
            assertTrue(crlCreateSession.forceCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS present in a new Full CRL
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            assertNotNull(revset);
            iter = revset.iterator();
            found = false;
            // log.debug(x509crl.getThisUpdate());
            // log.debug(x509crl.getThisUpdate().getTime());
            while (iter.hasNext()) {
                X509CRLEntry ce = (X509CRLEntry) iter.next();
                // log.debug(ce);
                if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
                    found = true;
                    // TODO: verify the reason code
                }
            }
            assertTrue(found);

            // Sleep 1 second so we don't issue the next CRL at the exact same time
            // as the revocation
            Thread.sleep(1000);
            // Create a new Delta CRL again...
            assertTrue(crlCreateSession.forceDeltaCRL(roleMgmgToken, testx509ca.getCAId()));
            // Check that our newly signed certificate IS NOT present in the new Delta CRL.
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), true);
            assertNotNull("Could not get CRL", crl);
            x509crl = CertTools.getCRLfromByteArray(crl);
            revset = x509crl.getRevokedCertificates();
            // log.debug(x509crl.getThisUpdate());
            if (revset != null) {
                iter = revset.iterator();
                found = false;
                while (iter.hasNext()) {
                    X509CRLEntry ce = (X509CRLEntry) iter.next();
                    // log.debug(ce);
                    // log.debug(ce.getRevocationDate().getTime());
                    if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
                        found = true;
                    }
                }
                assertFalse(found);
            } // If no revoked certificates exist at all, this test passed...        	
        } finally {
        	internalCertificateStoreSession.removeCertificate(CertTools.getSerialNumber(cert));
        }
    }

    // 
    // Helper methods
    //

    private X509Certificate createCert() throws Exception {
        // Make user that we know...
        EndEntityInformation user = new EndEntityInformation(USERNAME, "C=SE,O=AnaTom,CN=deltacrltest", testx509ca.getCAId(), null, "deltacrltest@anatom.se", EndEntityConstants.USER_ENDUSER, 0,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
        // user that we know exists...
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        int keyusage = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment;
        X509Certificate cert = (X509Certificate)testx509ca.generateCertificate(user, keys.getPublic(), keyusage, 10, cp, "00001");

        certificateStoreSession.storeCertificate(roleMgmgToken, cert, USERNAME, "1234", CertificateConstants.CERT_ACTIVE, 
        		CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, "footag", System.currentTimeMillis());
        assertNotNull("Failed to create certificate", cert);
        return cert;
    }

}
