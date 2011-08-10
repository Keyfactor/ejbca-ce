/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
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
 * Tests creating certificate with extended key usage.
 * 
 * Works similar to TestSignSession.
 *
 * Based on EJBCA version: ExtendedKeyUsageTest.java 11280 2011-01-28 15:42:09Z jeklund
 * 
 * @version $Id: CertificateCreateSessionTest.java 988 2011-08-10 14:33:46Z tomas $
 */
public class CertificateCreateSessionTest extends RoleUsingTestCase {
    
    private static KeyPair keys;
    private static final String X509CADN = "CN=TEST";
    private static CA testx509ca;

    private static CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);
    private static RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private static RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private CertificateProfileSessionRemote certProfileSession = JndiHelper.getRemoteSession(CertificateProfileSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = JndiHelper.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = JndiHelper.getRemoteSession(CertificateCreateSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = JndiHelper.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        testx509ca = CaSessionTest.createTestX509CA(X509CADN, null, false);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }
    
    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CertCreateSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CertCreateSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.EDITCERTIFICATEPROFILE.resource(), AccessRuleState.RULE_ACCEPT, true));
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
    		caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
    	} finally {
    		// Be sure to to this, even if the above fails
        	tearDownRemoveRole();
    	}
    }

    @Test
    public void test01CodeSigningExtKeyUsage() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        list.add("1.3.6.1.4.1.311.2.1.21"); // MS individual code signing
        list.add("1.3.6.1.4.1.311.2.1.22"); // MS commercial code signing
        certprof.setExtendedKeyUsage(list);
        String fingerprint = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            
            EndEntityInformation user = new EndEntityInformation("extkeyusagefoo","C=SE,O=AnaTom,CN=extkeyusagefoo",testx509ca.getCAId(),null,"foo@anatom.se",EndEntityConstants.USER_ENDUSER,0,cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");

        	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
            X509Certificate cert = (X509Certificate)resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
            //log.debug("Cert=" + cert.toString());
            List<String> ku = cert.getExtendedKeyUsage();
            assertEquals(2, ku.size());
            assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.21"));
            assertTrue(ku.contains("1.3.6.1.4.1.311.2.1.22"));
            
            // Check that the cert got created in the database
            Certificate cert1 = certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert));
            assertNotNull(cert1);
            assertEquals(fingerprint, CertTools.getFingerprintAsString(cert1));
        } finally {
        	certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
        	internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

    @Test
    public void test02SSHExtKeyUsage() throws Exception {
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        ArrayList<String> list = new ArrayList<String>();
        certprof.setExtendedKeyUsage(list);

        String fingerprint = null;
        try {
            int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);
            
        	EndEntityInformation user = new EndEntityInformation("extkeyusagefoo","C=SE,O=AnaTom,CN=extkeyusagefoo",testx509ca.getCAId(),null,"foo@anatom.se",EndEntityConstants.USER_ENDUSER,0,cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
        	user.setStatus(EndEntityConstants.STATUS_NEW);
        	user.setPassword("foo123");

        	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
            X509Certificate cert = (X509Certificate)resp.getCertificate();
        	assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
        	//log.debug("Cert=" + cert.toString());
        	List<String> ku = cert.getExtendedKeyUsage();
        	assertNull(ku);
        	internalCertStoreSession.removeCertificate(fingerprint);
        	
        	// Now add the SSH extended key usages
        	list.add("1.3.6.1.5.5.7.3.21"); // SSH client
        	list.add("1.3.6.1.5.5.7.3.22"); // SSH server
        	certprof.setExtendedKeyUsage(list);
        	certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);

            resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
            cert = (X509Certificate)resp.getCertificate();
        	assertNotNull("Failed to create certificate", cert);
            fingerprint = CertTools.getFingerprintAsString(cert);
        	//log.debug("Cert=" + cert.toString());
        	ku = cert.getExtendedKeyUsage();
        	assertEquals(2, ku.size());
        	assertTrue(ku.contains("1.3.6.1.5.5.7.3.21")); 
        	assertTrue(ku.contains("1.3.6.1.5.5.7.3.22"));
        	
            // Check that the cert got created in the database
            Certificate cert1 = certificateStoreSession.findCertificateByFingerprint(CertTools.getFingerprintAsString(cert));
            assertNotNull(cert1);
            assertEquals(CertTools.getFingerprintAsString(cert), CertTools.getFingerprintAsString(cert1));
        } finally {
        	certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
        	internalCertStoreSession.removeCertificate(fingerprint);
        }
    }

    @Test
    public void testDnFromRequestAllowDnOverride() throws Exception {

        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowDNOverride(true);
        assertTrue(certprof.getUseLdapDnOrder());
        String fp1 = null;
        String fp2 = null;
        try {
        	int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

        	EndEntityInformation user = new EndEntityInformation();
        	user.setType(EndEntityConstants.USER_ENDUSER);
        	user.setUsername("certcreatereq");
        	user.setCertificateProfileId(cpId);

        	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "certcreatereq", "foo123");
        	req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
        	req.setRequestDN("C=SE,O=PrimeKey,CN=noUserData");

        	// Make the call
        	X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        	assertNotNull("Failed to get response", resp);
        	Certificate cert = (X509Certificate)resp.getCertificate();
        	fp1 = CertTools.getFingerprintAsString(cert);
        	assertNotNull("Failed to create certificate", cert);
        	assertEquals("CN=noUserData,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));

        	// Test reversing DN, should make no difference since we override with requestDN
        	certprof.setUseLdapDnOrder(false);
        	certProfileSession.changeCertificateProfile(roleMgmgToken, "createCertTest", certprof);

        	resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        	assertNotNull("Failed to get response", resp);
        	cert = (X509Certificate)resp.getCertificate();
        	fp2 = CertTools.getFingerprintAsString(cert);
        	assertNotNull("Failed to create certificate", cert);
        	assertEquals("CN=noUserData,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));
        } finally {
        	certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
        	internalCertStoreSession.removeCertificate(fp1);
        	internalCertStoreSession.removeCertificate(fp2);
        }
    }

    @Test
    public void test27IssuanceRevocationReason() throws Exception {

        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        String fp1 = null;
        String fp2 = null;
        try {
        	int cpId = certProfileSession.addCertificateProfile(roleMgmgToken, "createCertTest", certprof);

        	EndEntityInformation user = new EndEntityInformation();
        	user.setType(EndEntityConstants.USER_ENDUSER);
        	user.setUsername("certcreatereq");
        	user.setDN("C=SE,O=PrimeKey,CN=noUserData");
        	user.setCertificateProfileId(cpId);

        	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), "certcreatereq", "foo123");
        	req.setIssuerDN(CertTools.getIssuerDN(testx509ca.getCACertificate()));
        	req.setRequestDN("C=SE,O=PrimeKey,CN=noUserData");

        	// Make the call
        	X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        	assertNotNull("Failed to get response", resp);
        	Certificate cert = (X509Certificate)resp.getCertificate();
        	fp1 = CertTools.getFingerprintAsString(cert);
        	assertNotNull("Failed to create certificate", cert);
        	assertEquals("CN=noUserData,O=PrimeKey,C=SE", CertTools.getSubjectDN(cert));
            // Check that it is active
            boolean isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertFalse(isRevoked);

            // Now add extended information with the revocation reason
            ExtendedInformation ei = new ExtendedInformation();
            ei.setIssuanceRevocationReason(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD);
            user.setExtendedinformation(ei);
            // create cert again
        	resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        	assertNotNull("Failed to get response", resp);
        	Certificate cert2 = (X509Certificate)resp.getCertificate();
        	fp2 = CertTools.getFingerprintAsString(cert2);
        	assertFalse(fp1.equals(fp2));
        	
            // Check that it is revoked
            isRevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert2), CertTools.getSerialNumber(cert2));
            assertTrue(isRevoked);
            CertificateStatus rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            assertEquals(RevokedCertInfo.NOT_REVOKED, rev.revocationReason);
            rev = certificateStoreSession.getStatus(CertTools.getIssuerDN(cert2), CertTools.getSerialNumber(cert2));
            assertEquals(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD, rev.revocationReason);
        } finally {
        	certProfileSession.removeCertificateProfile(roleMgmgToken, "createCertTest");
        	internalCertStoreSession.removeCertificate(fp1);
        	internalCertStoreSession.removeCertificate(fp2);
        }
    }

    @Test
    public void testAuthorization() throws Exception {
    	
    	// AuthenticationToken that does not have privileges to create a certificate
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CertProfileSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

    	EndEntityInformation user = new EndEntityInformation("certcreateauth","C=SE,O=AnaTom,CN=certcreateauth",testx509ca.getCAId(),null,"foo@anatom.se",EndEntityConstants.USER_ENDUSER,0,CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, 0, null);
    	user.setStatus(EndEntityConstants.STATUS_NEW);
    	user.setPassword("foo123");

    	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());    	

        try {
        	X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(adminTokenNoAuth, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        	assertTrue("should throw", false);
        } catch (AuthorizationDeniedException e) {
        	// NOPMD
        }
    }

}
