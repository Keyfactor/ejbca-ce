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
package org.cesecore.certificates.ca.catoken;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.internal.CATokenCacheManager;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the CA token session
 * 
 * @version $Id$
 */
public class CaTokenSessionTest extends RoleUsingTestCase {

    private CaTokenSessionRemote caTokenSession = JndiHelper.getRemoteSession(CaTokenSessionRemote.class);
    private CaSessionRemote caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);
    private CaTestSessionRemote caTestSession = JndiHelper.getRemoteSession(CaTestSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = JndiHelper.getRemoteSession(CertificateCreateSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = JndiHelper.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    private static final String X509CADN = "CN=TEST";
    private static CA testx509ca;
    private static KeyPair keys;
    
    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        testx509ca = CaSessionTest.createTestX509CA(X509CADN, null, false);
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CaTokenSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CaTokenSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);
        
        // Remove any lingering testca before starting the tests
        caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
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
    public void testCaTokenSession() throws Exception {
    	CA ca = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
    	int caid = testx509ca.getCAId();
    	Certificate cert = ca.getCACertificate();
    	// See that we can do something with the CAs to verify that everything was stored as we think
    	EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0,
    			0, EndEntityConstants.TOKEN_USERGEN, 0, null);
    	KeyPair keypair = KeyTools.genKeys("512", "RSA");
    	CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	Certificate usercert1 = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
    	usercert1.verify(cert.getPublicKey());

    	caTokenSession.generateKeys(roleMgmgToken, caid, "foo123".toCharArray(), true, false);
    	// Still old keys
    	CATokenCacheManager.instance().removeAll();
    	ca = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
    	usercert1 = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
    	PublicKey pubK = ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN); 
    	usercert1.verify(cert.getPublicKey());
    	usercert1.verify(pubK);

    	caTokenSession.activateNextSignKey(roleMgmgToken, caid, "foo123".toCharArray());
    	// Now new keys
    	CATokenCacheManager.instance().removeAll();
    	ca = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
    	try {
    	    // Not able to issue a new user certificate that the current CA certificate can not verify
    	    usercert1 = ca.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
    	    fail("Should throw");
    	} catch (InvalidKeyException e) {
            // NOPMD    	    
    	}
    }

    @Test
    public void testCaTokenActivateDeactivate() throws Exception {
    	// New CA with not default password
    	testx509ca = CaSessionTest.createTestX509CA(X509CADN, "userpin1", false);
    	try {
        	Certificate cacert = testx509ca.getCACertificate();
            caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
            caSession.addCA(roleMgmgToken, testx509ca);

            caTokenSession.activateCAToken(roleMgmgToken, testx509ca.getCAId(), "userpin1".toCharArray());
            CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
            assertEquals("CA Token should be active", CryptoToken.STATUS_ACTIVE, cainfo.getCATokenInfo().getTokenStatus());
        	// See that we can do something with the CAs to verify that everything was stored as we think
        	EndEntityInformation user = new EndEntityInformation("username", "CN=User", testx509ca.getCAId(), "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0,
        			0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        	user.setPassword("foo123");
        	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
        	Certificate cert = null;
        	try {
        		X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        		cert = resp.getCertificate();
        		//X509Certificate cert = (X509Certificate) certificateCreateSession.createCertificate(authenticationToken, user, null, keys.getPublic(), 0, null, null, null, "00001");
        		assertNotNull("Failed to create certificate", cert);
        		cert.verify(cacert.getPublicKey());
        	} finally {
        		internalCertificateStoreSession.removeCertificate(cert);
        	}

        	// Deactivate CA
        	caTokenSession.deactivateCAToken(roleMgmgToken, testx509ca.getCAId());
            cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
            assertEquals("CA Token should be offline", CryptoToken.STATUS_OFFLINE, cainfo.getCATokenInfo().getTokenStatus());
        	try {
        		X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        		cert = resp.getCertificate();
                assertTrue("Should trow", false);
        	} catch (CryptoTokenOfflineException e) {
        		// NOPMD
        	} finally {
        	    internalCertificateStoreSession.removeCertificate(cert);
        	}

        	try {
        		caTokenSession.activateCAToken(roleMgmgToken, testx509ca.getCAId(), "userpin1".toCharArray());
                cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
                assertEquals("CA Token should be active", CryptoToken.STATUS_ACTIVE, cainfo.getCATokenInfo().getTokenStatus());
        		X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
        		cert = resp.getCertificate();
        		assertNotNull("Failed to create certificate", cert);
        		cert.verify(cacert.getPublicKey()); 
        	} finally {
        		internalCertificateStoreSession.removeCertificate(cert);
        	}
    	} finally {
    		// restore the old test CA with default pwd
        	testx509ca = CaSessionTest.createTestX509CA(X509CADN, null, false);
    	}
	}

    @Test
    public void testCaSetProperties() throws Exception {
    	CAInfo info = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    	Properties prop = info.getCATokenInfo().getProperties();
    	assertEquals(5, prop.size());
    	assertNull(prop.getProperty("foo"));
    	caTokenSession.setTokenProperty(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), "foo", "bar");
    	info = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    	prop = info.getCATokenInfo().getProperties();
    	assertEquals(6, prop.size());
    	assertEquals("bar", prop.getProperty("foo"));

    	caTokenSession.setTokenProperty(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), "foo", "bar123");
    	info = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    	prop = info.getCATokenInfo().getProperties();
    	assertEquals(6, prop.size());
    	assertEquals("bar123", prop.getProperty("foo"));
    	
    	assertEquals("privatesignkeyalias", prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));
    	caTokenSession.setTokenProperty(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "newAlias");
    	info = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    	prop = info.getCATokenInfo().getProperties();
    	assertEquals(6, prop.size());
    	assertEquals("newAlias", prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));    	
	}

    @Test
    public void testGenerateGetAndDeleteKeys() throws Exception {
    	Certificate cacert = testx509ca.getCACertificate();

    	caTokenSession.generateKeyPair(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), "512", "newAlias");
    	
    	// See that we can do something with the CAs to verify that everything was stored as we think
    	EndEntityInformation user = new EndEntityInformation("username", "CN=User", testx509ca.getCAId(), "rfc822Name=user@user.com", "user@user.com", EndEntityConstants.USER_ENDUSER, 0,
    			0, EndEntityConstants.TOKEN_USERGEN, 0, null);
    	user.setPassword("foo123");
    	SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());
    	Certificate cert = null;
    	try {
    		X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
    		cert = resp.getCertificate();
    		//X509Certificate cert = (X509Certificate) certificateCreateSession.createCertificate(authenticationToken, user, null, keys.getPublic(), 0, null, null, null, "00001");
    		assertNotNull("Failed to create certificate", cert);
    		// Verify with old CA-cert, we only generated new keys on the token, didn't activate them as CA keys
    		cert.verify(cacert.getPublicKey());
    	} finally {
    		internalCertificateStoreSession.removeCertificate(cert);
    	}
    	// If we retrieve the public key as key purpose, it should be the old one, matching the old ce-cert
    	final PublicKey oldpk = caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN);
    	assertEquals(cacert.getPublicKey(), oldpk);
    	// If we retrieve the newly generated public key, from alias, it should not be the same 
    	final PublicKey newpk = caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), "newAlias");
    	assertFalse(cacert.getPublicKey().equals(newpk));

    	// Activate the new keys as CA signing keys
    	caTokenSession.setTokenProperty(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "newAlias");
    	CAInfo info = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    	Properties prop = info.getCATokenInfo().getProperties();
    	assertEquals("newAlias", prop.getProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING));    	

    	// Now we should not be able to verify a new certificate with old CA certificate
    	try {
            try {
                certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
                fail("should not be able to create certificate");
            } catch (CertificateCreateException e) {
                // NOPMD
            }
    	} finally {
    		internalCertificateStoreSession.removeCertificate(cert);
    	}
    	// If we retrieve the public key as key purpose, it should be the new one, not matching the old ce-cert
    	final PublicKey newpk1 = caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN);
    	assertFalse(cacert.getPublicKey().equals(newpk1));
    	// If we retrieve the newly generated public key, from alias, it should not be the same either 
    	final PublicKey newpk2 = caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), "newAlias");
    	assertFalse(cacert.getPublicKey().equals(newpk2));
    	// If we retrieve the old public key, from alias, it should be the same 
    	final PublicKey oldpk1 = caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CAToken.SOFTPRIVATESIGNKEYALIAS);
    	assertEquals(cacert.getPublicKey(), oldpk1);
    	
    	// Delete the old key
    	caTokenSession.deleteTokenEntry(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CAToken.SOFTPRIVATESIGNKEYALIAS);
    	// We should not be able to retrieve the key now
    	try {
    		caTokenSession.getPublicKey(roleMgmgToken, testx509ca.getCAId(), "foo123".toCharArray(), CAToken.SOFTPRIVATESIGNKEYALIAS);
    		assertTrue("Should throw", false);
    	} catch (CryptoTokenOfflineException e) {
    		// NOPMD
    	}
	}

}
