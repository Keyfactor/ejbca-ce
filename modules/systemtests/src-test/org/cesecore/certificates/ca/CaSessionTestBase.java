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
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.catoken.CaTokenSessionRemote;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.internal.CATokenCacheManager;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;

/**
 * Tests the CA session bean.
 * 
 * @version $Id$
 */
public class CaSessionTestBase extends RoleUsingTestCase {

    private static final Logger log = Logger.getLogger(CaSessionTestBase.class);

    private CA testx509ca;
    private CA testcvcca;
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class);
    private CaTokenSessionRemote caTokenSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTokenSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);

    public CaSessionTestBase(CA x509ca, CA cvcca) {
    	this.testx509ca = x509ca;
    	this.testcvcca = cvcca;
    }
    
    public void setUp() throws Exception {  //NOPMD: this is not a test case    	
    	// Set up base role that can edit roles
    	setUpAuthTokenAndRole("CaSessionTest");

    	// Now we have a role that can edit roles, we can edit this role to include more privileges
    	RoleData role = roleAccessSession.findRole("CaSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECRL.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        // Remove any lingering testca before starting the tests
        if (testx509ca != null) {
            caSession.removeCA(roleMgmgToken, testx509ca.getCAId());        	
        }
        if (testcvcca != null) {
        	caSession.removeCA(roleMgmgToken, testcvcca.getCAId());
        }
    }

    public void tearDown() throws Exception { //NOPMD: this is not a test case
        // Remove any testca before exiting tests
    	try {
            if (testx509ca != null) {
                caSession.removeCA(roleMgmgToken, testx509ca.getCAId());        	
            }
            if (testcvcca != null) {
            	caSession.removeCA(roleMgmgToken, testcvcca.getCAId());
            }
    	} finally {
    		// Be sure to to this, even if the above fails
        	tearDownRemoveRole();
    	}
    }

    public void testAddRenameAndRemoveX509CA() throws Exception {
        caSession.addCA(roleMgmgToken, testx509ca);
        // Try to add the same CA again
        try {
            caSession.addCA(roleMgmgToken, testx509ca);
            assertTrue("Should throw", false);
        } catch (CAExistsException e) {
            // NOPMD
        }
        CA ca1 = caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        CA ca2 = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals(ca1.getCAId(), ca2.getCAId());
        assertEquals(ca1.getName(), ca2.getName());
        assertEquals(ca1.getSubjectDN(), ca2.getSubjectDN());
        assertEquals(CAConstants.CA_ACTIVE, ca1.getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca2.getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca1.getCAInfo().getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca2.getCAInfo().getStatus());
        assertEquals(CryptoToken.STATUS_ACTIVE, ca1.getCAToken().getTokenStatus());
        assertEquals(CryptoToken.STATUS_ACTIVE, ca1.getCAToken().getCryptoToken().getTokenStatus());
        assertEquals(CryptoToken.STATUS_ACTIVE, ca1.getCAInfo().getCATokenInfo().getTokenStatus());
        assertEquals(CryptoToken.STATUS_ACTIVE, ca2.getCAInfo().getCATokenInfo().getTokenStatus());
        Date now = new Date();
        assertTrue("CA expire time should be after now: "+ca1.getExpireTime(), now.before(ca1.getExpireTime()));
        assertTrue("CA expire time should be after now: "+ca2.getExpireTime(), now.before(ca2.getExpireTime()));
        assertTrue("CAInfo expire time should be after now: "+ca1.getCAInfo().getExpireTime(), now.before(ca1.getCAInfo().getExpireTime()));
        assertTrue("CAInfo expire time should be after now: "+ca2.getCAInfo().getExpireTime(), now.before(ca2.getCAInfo().getExpireTime()));

        // See that we can do something with the CAs to verify that everything was stored as we think
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0,
                0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate usercert1 = ca1.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertEquals("CN=User", CertTools.getSubjectDN(usercert1));
        Certificate usercert2 = ca2.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertEquals("CN=User", CertTools.getSubjectDN(usercert2));

        caSession.renameCA(roleMgmgToken, testx509ca.getName(), "TEST1");
        try {
        	caTestSession.getCA(roleMgmgToken, testx509ca.getName());
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        ca1 = caTestSession.getCA(roleMgmgToken, "TEST1");
        assertEquals(testx509ca.getCAId(), ca1.getCAId());
        try {
            caSession.renameCA(roleMgmgToken, "TEST1", "TEST1");
            assertTrue("Should throw", false);
        } catch (CAExistsException e) {
            // NOPMD
        }
        // Something non existing, should throw CADoesntExistException
        boolean caught = false;
        try {
            caSession.renameCA(roleMgmgToken, "TEST86868658334nn", "TEST74736363dd");
        } catch (CADoesntExistsException e) {
            caught = true;
        }
        assertTrue(caught);
        // Rename back again
        caSession.renameCA(roleMgmgToken, "TEST1", testx509ca.getName());
        try {
        	caTestSession.getCA(roleMgmgToken, "TEST1");
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        
        // Test edit
        CA ca = caTestSession.getCA(roleMgmgToken, "TEST");
        CAInfo cainfo = ca.getCAInfo();
        assertEquals(testx509ca.getCAId(), ca2.getCAId());
        assertEquals(0, cainfo.getCRLIssueInterval());
        cainfo.setCRLIssueInterval(50);
        caSession.editCA(roleMgmgToken, cainfo);
        ca = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals(50, ca.getCRLIssueInterval());
        assertEquals(50, ca.getCAInfo().getCRLIssueInterval());

        // Test edit using a new "edit" CAInfo
        X509CAInfo newinfo = new X509CAInfo(cainfo.getCAId(), cainfo.getValidity(), cainfo.getCATokenInfo(), "new description", 
        		cainfo.getCRLPeriod(), cainfo.getCRLIssueInterval(), cainfo.getCRLOverlapTime(), cainfo.getDeltaCRLPeriod(), 
        		cainfo.getCRLPublishers(), true, false, true, false, null, null, null, null,  null, cainfo.getFinishUser(), 
        		cainfo.getExtendedCAServiceInfos(), true, cainfo.getApprovalSettings(), cainfo.getNumOfReqApprovals(), false, true, 
        		false, false, cainfo.getIncludeInHealthCheck(), cainfo.isDoEnforceUniquePublicKeys(), cainfo.isDoEnforceUniqueDistinguishedName(), 
        		cainfo.isDoEnforceUniqueSubjectDNSerialnumber(), cainfo.isUseCertReqHistory(), cainfo.isUseUserStorage(), cainfo.isUseCertificateStorage(), null);
        newinfo.setSubjectDN(cainfo.getSubjectDN());
        newinfo.setName(cainfo.getName());
        caSession.editCA(roleMgmgToken, newinfo);
        ca = caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals("new description", ca.getDescription());
        
        // Remove
        caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
        try {
        	caTestSession.getCA(roleMgmgToken, testx509ca.getName());
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        try {
        	caTestSession.getCA(roleMgmgToken, "TEST1");
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }        
    } // testAddRenameAndRemoveX509CA

    public void testAddAndGetCAWithDifferentCaid() throws Exception {
        caSession.addCA(roleMgmgToken, testx509ca);
        CA ca1 = caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        Certificate cert = testx509ca.getCACertificate();
        assertEquals(ca1.getCAId(), testx509ca.getCAId());
        // CA certificate subjectDN gives the correct caid here
        assertEquals(ca1.getCAId(), CertTools.getSubjectDN(cert).hashCode());
        // Now edit the CA to change the CA-certificate to something with a different subjectDN
        String cadn = "CN=TEST,O=Foo,C=SE";
        CAToken catoken = ca1.getCAToken();
        Collection<Certificate> cachain = new ArrayList<Certificate>();
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", catoken.getPrivateKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
        		catoken.getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN), "SHA256WithRSA", true, catoken.getCryptoToken()
        		.getSignProviderName());
        assertNotNull(cacert);
        cachain.add(cacert);
        CAInfo cainfo = ca1.getCAInfo();
        cainfo.setCertificateChain(cachain);
        caSession.editCA(roleMgmgToken, cainfo);
        // Now get the CA and verify that the certificate was changed
        CA ca2 = caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        Certificate cert2 = ca2.getCACertificate();
        assertEquals(ca2.getCAId(), testx509ca.getCAId());
        // CA certificate subjectDN gives the correct caid here
        int certcaid = CertTools.getSubjectDN(cert2).hashCode();
        assertFalse("CAIds should be different using new CA certifciate", ca2.getCAId() == certcaid);
        // See if we can get the CA using the "bad" ca id as well
        // First time should find it, and it should add an entry to the "cache" of CAIds in CaSessionBean
        // Second time uses this cache, therefore we will try two times to make sure that both lookup and cache works
        CA ca3 = caTestSession.getCA(roleMgmgToken, certcaid);
        assertNotNull(ca3);
        assertEquals(ca3.getCAId(), testx509ca.getCAId());
        CA ca4 = caTestSession.getCA(roleMgmgToken, certcaid);
        assertNotNull(ca4);
        assertEquals(ca4.getCAId(), testx509ca.getCAId());
    } // testAddAndGetCAWithDifferentCaid

    public void testAddRenameAndRemoveCVCCA() throws Exception {
        caSession.addCA(roleMgmgToken, testcvcca);
        // Try to add the same CA again
        try {
            caSession.addCA(roleMgmgToken, testcvcca);
            assertTrue("Should throw", false);
        } catch (CAExistsException e) {
            // NOPMD
        }
        CA ca1 = caTestSession.getCA(roleMgmgToken, testcvcca.getCAId());
        CA ca2 = caTestSession.getCA(roleMgmgToken, testcvcca.getName());
        assertEquals(ca1.getCAId(), ca2.getCAId());
        assertEquals(ca1.getName(), ca2.getName());
        assertEquals(ca1.getSubjectDN(), ca2.getSubjectDN());

        // See that we can do something with the CAs to verify that everything was stored as we think
        EndEntityInformation user = new EndEntityInformation("username", "CN=User001,C=SE", 666, null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0,
                0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        Certificate usercert1 = ca1.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertEquals("CN=User001,C=SE", CertTools.getSubjectDN(usercert1));
        Certificate usercert2 = ca2.generateCertificate(user, keypair.getPublic(), 0, null, 10L, cp, "00000");
        assertEquals("CN=User001,C=SE", CertTools.getSubjectDN(usercert2));

        caSession.renameCA(roleMgmgToken, testcvcca.getName(), "TESTCVC1");
        try {
        	caTestSession.getCA(roleMgmgToken, testcvcca.getName());
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        ca1 = caTestSession.getCA(roleMgmgToken, "TESTCVC1");
        assertEquals(testcvcca.getCAId(), ca1.getCAId());
        try {
            caSession.renameCA(roleMgmgToken, "TESTCVC1", "TESTCVC1");
            assertTrue("Should throw", false);
        } catch (CAExistsException e) {
            // NOPMD
        }
        // Something non existing, should throw CADoesntExistException
        boolean caught = false;
        try {
            caSession.renameCA(roleMgmgToken, "TESTCVC86868658334nn", "TESTCVC74736363dd");
        } catch (CADoesntExistsException e) {
            caught = true;
        }
        assertTrue(caught);
        // Rename back again
        caSession.renameCA(roleMgmgToken, "TESTCVC1", testcvcca.getName());
        try {
        	caTestSession.getCA(roleMgmgToken, "TESTCVC1");
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        ca2 = caTestSession.getCA(roleMgmgToken, testcvcca.getName());
        assertEquals(testcvcca.getCAId(), ca2.getCAId());

        caSession.removeCA(roleMgmgToken, testcvcca.getCAId());
        try {
        	caTestSession.getCA(roleMgmgToken, testcvcca.getName());
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
        try {
        	caTestSession.getCA(roleMgmgToken, "TESTCVC1");
            assertTrue("Should throw", false);
        } catch (CADoesntExistsException e) {
            // NOPMD
        }
    }

    public void addCAGenerateKeysLater(CA ca, String cadn, String tokenpwd) throws Exception {
    	X509Certificate cert = null;
    	try {
        	// Store CA
        	caSession.addCA(roleMgmgToken, ca);
        	// Test to get the CAInfo with signature test, will work because status of token is ok, even though there are no keys
        	caSession.getCAInfo(roleMgmgToken, ca.getCAId(), true);
        	// Generate keys, will audit log
        	caTokenSession.activateCAToken(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray());
        	caTokenSession.generateKeys(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), false, true);
        	CATokenCacheManager.instance().removeAll();
            
        	// Now create a CA certificate
        	CAInfo info = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
        	Collection<Certificate> certs = info.getCertificateChain(); 
        	assertEquals(0, certs.size());

            // We need the CA public key, since we activated the newly generated key, we know that it has a key purpose now
            PublicKey pk = caTokenSession.getPublicKey(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            
            EndEntityInformation user = new EndEntityInformation("casessiontestca", cadn, ca.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");
        	SimpleRequestMessage req = new SimpleRequestMessage(pk, user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
            cert = (X509Certificate)resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            // Verifies with CA token?
            cert.verify(pk);
            // Add the new CA cert
            certs.add(cert);
            info.setCertificateChain(certs);
            caSession.editCA(roleMgmgToken, info);
            
            // Get it again
            CAInfo info1 = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
        	Collection<Certificate> certs1 = info1.getCertificateChain(); 
        	assertEquals(1, certs1.size());
        	Certificate cert1 = certs1.iterator().next();
            cert1.verify(pk);
            
        	// Test to get the CAInfo with signature test again, should also work, now with new keys
        	caSession.getCAInfo(roleMgmgToken, ca.getCAId(), true);
    	} finally {
    		caSession.removeCA(roleMgmgToken, ca.getCAId());
    		internalCertStoreSession.removeCertificate(cert);
    	}    	
    }
    
//    public void addCAUseSessionBeanToGenerateKeys(CA ca, String cadn, String tokenpwd) throws Exception {
//    	// Generate CA keys
//    	CryptoToken newtoken = tokenSession.generateKeyPair(roleMgmgToken, ca.getCAToken().getCryptoToken(), tokenpwd.toCharArray(), "512", "privatesignkeyalias");
//    	CAToken catoken = ca.getCAToken();
//    	catoken.setCryptoToken(newtoken);
//    	ca.setCAToken(catoken);
//    	ca.getCAToken().getCryptoToken().activate(tokenpwd.toCharArray());
//    	PublicKey pubK = ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
//    	assertNotNull(pubK);
//    	Certificate cert = null;
//    	try {
//        	// Store CA
//        	caSession.addCA(roleMgmgToken, ca);
//        	caTokenSession.activateCAToken(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray());
//        	// Now create a CA certificate
//        	CAInfo info = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
//        	Collection<Certificate> certs = info.getCertificateChain(); 
//        	assertEquals(0, certs.size());
//
//            EndEntityInformation user = new EndEntityInformation("casessiontestca",cadn,ca.getCAId(),null,null,new EndEntityType(EndEntityTypes.USER_ENDUSER),0,CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, 0, null);
//            user.setStatus(EndEntityConstants.STATUS_NEW);
//            user.setPassword("foo123");
//        	SimpleRequestMessage req = new SimpleRequestMessage(pubK, user.getUsername(), user.getPassword());
//            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
//            cert = (X509Certificate)resp.getCertificate();
//            assertNotNull("Failed to create certificate", cert);
//            // Verifies with CA token?
//            cert.verify(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
//            // Add the new CA cert
//            certs.add(cert);
//            info.setCertificateChain(certs);
//            caSession.editCA(roleMgmgToken, info);
//            
//            // Get it again
//            CAInfo info1 = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
//        	Collection<Certificate> certs1 = info1.getCertificateChain(); 
//        	assertEquals(1, certs1.size());
//        	Certificate cert1 = certs1.iterator().next();
//            cert1.verify(ca.getCAToken().getPublicKey(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
//    	} finally {
//    		caSession.removeCA(roleMgmgToken, ca.getCAId());
//    		internalCertStoreSession.removeCertificate(cert);
//    	}    	
//    }

    public void addCAUseSessionBeanToGenerateKeys2(CA ca, String cadn, String tokenpwd) throws Exception {
    	// Generate CA keys
    	Certificate cert = null;
    	try {
            caSession.addCA(roleMgmgToken, ca);
        	caTokenSession.generateKeyPair(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), "1024", "signKeyAlias");
        	PublicKey pubK = caTokenSession.getPublicKey(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), "signKeyAlias");
        	assertNotNull(pubK);
        	caTokenSession.setTokenProperty(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signKeyAlias");
        	caTokenSession.setTokenProperty(roleMgmgToken, ca.getCAId(), tokenpwd.toCharArray(), CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signKeyAlias");
        	// Now create a CA certificate
        	CAInfo info = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
        	Collection<Certificate> certs = info.getCertificateChain(); 
        	assertEquals(0, certs.size());

            EndEntityInformation user = new EndEntityInformation("casessiontestca", ca.getSubjectDN(), ca.getCAId(), null, null,
                    new EndEntityType(EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");
        	SimpleRequestMessage req = new SimpleRequestMessage(pubK, user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage)certificateCreateSession.createCertificate(roleMgmgToken, user, req, org.cesecore.certificates.certificate.request.X509ResponseMessage.class);
            cert = (X509Certificate)resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            // Verifies with CA token?
            cert.verify(pubK);
            // Add the new CA cert
            certs.add(cert);
            info.setCertificateChain(certs);
            caSession.editCA(roleMgmgToken, info);
            
            // Get it again
            CAInfo info1 = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
        	Collection<Certificate> certs1 = info1.getCertificateChain(); 
        	assertEquals(1, certs1.size());
        	Certificate cert1 = certs1.iterator().next();
            cert1.verify(pubK);
            
        	// Test generate a CRL as well
        	// We should not have any CRL generated now
        	byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
        	assertNull(crl);
        	try {
            	// Create a CRL with this PKCS11 CA
            	boolean result = crlCreateSession.forceCRL(roleMgmgToken, ca.getCAId());
            	assertTrue(result);
            	// We should now have a CRL generated
            	crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
            	assertNotNull(crl);        	
            	// Check that it is signed by the correct public key
            	X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
            	xcrl.verify(pubK);
        	} catch (Exception e) {
        		log.error("Error: ", e);
        		assertTrue("Should not throw here", false);
        	} finally {
        		// Remove it to clean database
        		internalCertStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(crl));    		
        	}
    	} finally {
    		caSession.removeCA(roleMgmgToken, ca.getCAId());
    		internalCertStoreSession.removeCertificate(cert);
    	}    	
    }

    public void extendedCAServices(CA ca) throws Exception {
    	// Generate CA keys
    	Certificate cert = null;
    	try {
            caSession.addCA(roleMgmgToken, ca);
            CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, "TEST");
            ArrayList<ExtendedCAServiceInfo> newlist = new ArrayList<ExtendedCAServiceInfo>();
            ExtendedCAServiceInfo myinfo = new TestExtendedCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE);
            newlist.add(myinfo);
            cainfo.setExtendedCAServiceInfos(newlist);
            caSession.editCA(roleMgmgToken, cainfo);
            cainfo = caSession.getCAInfo(roleMgmgToken, "TEST");
            Collection<ExtendedCAServiceInfo> infos = cainfo.getExtendedCAServiceInfos();
            boolean ok = false;
            for (ExtendedCAServiceInfo info : infos) {
    			if (info.getType() == TestExtendedCAServiceInfo.type) {
    				if (info.getStatus() == ExtendedCAServiceInfo.STATUS_INACTIVE) {
    					ok = true;
    				}
    			}
    		}
            assertTrue("extended CA service should not have been activated", ok);
            
            ArrayList<ExtendedCAServiceInfo> newlist1 = new ArrayList<ExtendedCAServiceInfo>();
            ExtendedCAServiceInfo myinfo1 = new TestExtendedCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE);
            newlist1.add(myinfo1);
            cainfo.setExtendedCAServiceInfos(newlist1);
            caSession.editCA(roleMgmgToken, cainfo);
            cainfo = caSession.getCAInfo(roleMgmgToken, "TEST");
            infos = cainfo.getExtendedCAServiceInfos();
            ok = false;
            for (ExtendedCAServiceInfo info : infos) {
    			if (info.getType() == TestExtendedCAServiceInfo.type) {
    				if (info.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
    					ok = true;
    				}
    			}
    		}
            assertTrue("extended CA service should have been activated", ok);
            
    	} finally {
    		caSession.removeCA(roleMgmgToken, ca.getCAId());
    		internalCertStoreSession.removeCertificate(cert);
    	}    	
    }

    public void testAuthorization() throws Exception {
    	
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 

        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CaSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);

        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());

        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(principals, credentials);

    	caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
    	// Try to add and edit CAs with and admin that does not have authorization
    	try {
    		try {
    			caSession.addCA(adminTokenNoAuth, testx509ca);
    			assertTrue("Should throw", false);
    		} catch (AuthorizationDeniedException e) {
    			// NOPMD
    		}
    		caSession.addCA(roleMgmgToken, testx509ca);

    		try {
    			caSession.renameCA(adminTokenNoAuth, testx509ca.getName(), "fooName");
    			assertTrue("Should throw", false);
    		} catch (AuthorizationDeniedException e) {
    			// NOPMD
    		}

    		try {
    			caSession.removeCA(adminTokenNoAuth, testx509ca.getCAId());
    			assertTrue("Should throw", false);
    		} catch (AuthorizationDeniedException e) {
    			// NOPMD
    		}

    		try {
        		caSession.getCAInfo(adminTokenNoAuth, testx509ca.getCAId());
    			assertTrue("Should throw", false);
    		} catch (AuthorizationDeniedException e) {
    			// NOPMD
    		}

    		CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    		assertEquals(0, cainfo.getCRLIssueInterval());
    		assertEquals(CAConstants.CA_ACTIVE, cainfo.getStatus());
    		cainfo.setCRLIssueInterval(50);
    		cainfo.setStatus(CAConstants.CA_OFFLINE);
    		try {
    			caSession.editCA(adminTokenNoAuth, cainfo);
    		} catch (AuthorizationDeniedException e) {
    			// NOPMD
    		}
    		// This should work though
    		caSession.editCA(roleMgmgToken, cainfo);
    		cainfo = caSession.getCAInfo(roleMgmgToken, testx509ca.getCAId());
    		assertEquals(50, cainfo.getCRLIssueInterval());
    		assertEquals(CAConstants.CA_OFFLINE, cainfo.getStatus());
    	} finally {
        	caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
    	}
    }

}
