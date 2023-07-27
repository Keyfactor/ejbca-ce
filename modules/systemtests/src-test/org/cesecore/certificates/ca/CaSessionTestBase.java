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

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.cesecore.CaTestUtils;
import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.KeyGenParams;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Tests the CA session bean.
 */
public class CaSessionTestBase extends RoleUsingTestCase {
    
    private CA testx509ca;
    private CA testcvcca;
    
    protected CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    protected CaTestSessionRemote caTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    protected CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    protected GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class, EjbRemoteHelper.MODULE_CESECORE);
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaSessionTestBase"));
    
    public CaSessionTestBase(CA x509ca, CA cvcca) {
    	this.testx509ca = x509ca;
    	this.testcvcca = cvcca;
    }
    
    public void setUp() throws Exception {  //NOPMD: this is not a test case    	
    	// Set up base role that can edit roles
    	super.setUpAuthTokenAndRole(null, "CaSessionTestBase", Arrays.asList(
    	        StandardRules.CAADD.resource(),
    	        StandardRules.CAEDIT.resource(),
    	        StandardRules.CAREMOVE.resource(),
    	        StandardRules.CAACCESSBASE.resource(),
    	        StandardRules.CREATECERT.resource(),
    	        StandardRules.CREATECRL.resource(),
    	        CryptoTokenRules.BASE.resource()
    	        ), null);
        // Remove any lingering testca before starting the tests, but not associated crypto tokens
    	// CaSessionTestBase depends on that the Crypto Token is not removed so it can be re-used.
    	// a bad circular dependency
        if (testx509ca != null) {
            caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());         
        }
        if (testcvcca != null) {
            caSession.removeCA(alwaysAllowToken, testcvcca.getCAId());
        }
    }

    public void tearDown() throws Exception { //NOPMD: this is not a test case
        // Remove any testca before exiting tests, but not associated crypto tokens
        // CaSessionTestBase depends on that the Crypto Token is not removed so it can be re-used.
        // a bad circular dependency
    	try {
            if (testx509ca != null) {
                caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());         
            }
            if (testcvcca != null) {
                caSession.removeCA(alwaysAllowToken, testcvcca.getCAId());
            }
    	} finally {
    		// Be sure to do this, even if the above fails
    	    super.tearDownRemoveRole();
    	}
    }

    public void addRenameAndRemoveX509CA() throws Exception {
        cleanUpAnyExistingCa(testx509ca.getCAId(), testx509ca.getName());
        caSession.addCA(roleMgmgToken, testx509ca);
        // Try to add the same CA again
        try {
            caSession.addCA(roleMgmgToken, testx509ca);
            fail("Should throw");
        } catch (CAExistsException e) {
            // NOPMD
        }
        CA ca1 = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        CA ca2 = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals(ca1.getCAId(), ca2.getCAId());
        assertEquals(ca1.getName(), ca2.getName());
        assertEquals(ca1.getSubjectDN(), ca2.getSubjectDN());
        assertEquals(CAConstants.CA_ACTIVE, ca1.getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca2.getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca1.getCAInfo().getStatus());
        assertEquals(CAConstants.CA_ACTIVE, ca2.getCAInfo().getStatus());
        assertTrue("Expected status " + CryptoToken.STATUS_ACTIVE, cryptoTokenManagementSession.isCryptoTokenStatusActive(roleMgmgToken, ca1.getCAToken().getCryptoTokenId()));
        assertTrue("Expected status " + CryptoToken.STATUS_ACTIVE, cryptoTokenManagementSession.isCryptoTokenStatusActive(roleMgmgToken, ca2.getCAToken().getCryptoTokenId()));
        Date now = new Date();
        assertTrue("CA expire time should be after now: "+ca1.getExpireTime(), now.before(ca1.getExpireTime()));
        assertTrue("CA expire time should be after now: "+ca2.getExpireTime(), now.before(ca2.getExpireTime()));
        assertTrue("CAInfo expire time should be after now: "+ca1.getCAInfo().getExpireTime(), now.before(ca1.getCAInfo().getExpireTime()));
        assertTrue("CAInfo expire time should be after now: "+ca2.getCAInfo().getExpireTime(), now.before(ca2.getCAInfo().getExpireTime()));

         /* This is pretty messed up.. we only test that the CA is working in the client VM..*/
        EndEntityInformation user = new EndEntityInformation("username", "CN=User", 666, "rfc822Name=user@user.com", "user@user.com", new EndEntityType(EndEntityTypes.ENDUSER), 0,
                0, EndEntityConstants.TOKEN_USERGEN, null);
        KeyPair keypair = KeyTools.genKeys("512", "RSA");
        CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CryptoToken cryptoToken1 = cryptoTokenManagementProxySession.getCryptoToken(ca1.getCAToken().getCryptoTokenId());
         final AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration)
                globalConfigurationSession.getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);        Certificate usercert1 = ca1.generateCertificate(cryptoToken1, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert1));
        CryptoToken cryptoToken2 = cryptoTokenManagementProxySession.getCryptoToken(ca2.getCAToken().getCryptoTokenId());
        Certificate usercert2 = ca2.generateCertificate(cryptoToken2, user, keypair.getPublic(), 0, null, "10d", cp, "00000", cceConfig);
        assertEquals("CN=User", CertTools.getSubjectDN(usercert2));
        

        String oldname = testx509ca.getName();
        caSession.renameCA(roleMgmgToken, testx509ca.getName(), "TEST1");
        assertNull("CA by name of " +  oldname + " shouldn't exist.", caTestSession.getCA(roleMgmgToken, oldname));

        ca1 = (CA)caTestSession.getCA(roleMgmgToken, "TEST1");
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
        assertNull("CA by name of " +  "TEST1" + " shouldn't exist.", caTestSession.getCA(roleMgmgToken, "TEST1"));
        
        // Test edit
        CA ca = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        X509CAInfo cainfo = (X509CAInfo) ca.getCAInfo();
        assertEquals(testx509ca.getCAId(), ca2.getCAId());
        assertEquals(0, cainfo.getCRLIssueInterval());
        cainfo.setCRLIssueInterval(50);
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC, cainfo.getCAToken().getKeySequenceFormat());
        assertEquals("00000", cainfo.getCAToken().getKeySequence());
        cainfo.getCAToken().setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC);
        cainfo.getCAToken().setKeySequence("SE002");
        caSession.editCA(roleMgmgToken, cainfo);
        ca = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals(50, ca.getCRLIssueInterval());
        assertEquals(50, ca.getCAInfo().getCRLIssueInterval());
        assertEquals(StringTools.KEY_SEQUENCE_FORMAT_ALPHANUMERIC, ca.getCAInfo().getCAToken().getKeySequenceFormat());
        assertEquals("SE002", ca.getCAInfo().getCAToken().getKeySequence());

        // Test edit using a new "edit" CAInfo
        X509CAInfo.X509CAInfoBuilder x509CAInfoBuilder = new X509CAInfo.X509CAInfoBuilder()
                .setCaId(cainfo.getCAId())
                .setEncodedValidity(cainfo.getEncodedValidity())
                .setCaToken(cainfo.getCAToken()).setDescription("new description")
                .setCaSerialNumberOctetSize(20)
                .setCrlPeriod(cainfo.getCRLPeriod())
                .setCrlIssueInterval(cainfo.getCRLIssueInterval())
                .setCrlOverlapTime(cainfo.getCRLOverlapTime())
                .setDeltaCrlPeriod(cainfo.getDeltaCRLPeriod())
                .setGenerateCrlUponRevocation(cainfo.isGenerateCrlUponRevocation())
                .setCrlPublishers(cainfo.getCRLPublishers())
                .setValidators(new ArrayList<Integer>())
                .setUseAuthorityKeyIdentifier(true)
                .setAuthorityKeyIdentifierCritical(false)
                .setUseCrlNumber(true)
                .setCrlNumberCritical(false)
                .setDefaultCrlDistPoint(null)
                .setDefaultCrlIssuer(null)
                .setDefaultOcspCerviceLocator(null)
                .setAuthorityInformationAccess(null)
                .setCertificateAiaDefaultCaIssuerUri(null)
                .setNameConstraintsPermitted(null)
                .setNameConstraintsExcluded(null)
                .setCaDefinedFreshestCrl(null)
                .setFinishUser(cainfo.getFinishUser())
                .setExtendedCaServiceInfos(cainfo.getExtendedCAServiceInfos())
                .setUseUtf8PolicyText(true)
                .setApprovals(cainfo.getApprovals())
                .setUsePrintableStringSubjectDN(false)
                .setUseLdapDnOrder(true)
                .setUseCrlDistributionPointOnCrl(false)
                .setCrlDistributionPointOnCrlCritical(false)
                .setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck())
                .setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys())
                .setDoEnforceKeyRenewal(cainfo.isDoEnforceKeyRenewal())
                .setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName())
                .setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber())
                .setUseCertReqHistory(cainfo.isUseCertReqHistory())
                .setUseUserStorage(cainfo.isUseUserStorage())
                .setUseCertificateStorage(cainfo.isUseCertificateStorage())
                .setAcceptRevocationNonExistingEntry(cainfo.isAcceptRevocationNonExistingEntry())
                .setCmpRaAuthSecret(null)
                .setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL())
                .setDefaultCertProfileId(-1)
                .setUseNoConflictCertificateData(false)
                .setUsePartitionedCrl(cainfo.getUsePartitionedCrl())
                .setCrlPartitions(0)
                .setSuspendedCrlPartitions(0);
        X509CAInfo newinfo =  x509CAInfoBuilder.buildForUpdate();
        newinfo.setSubjectDN(cainfo.getSubjectDN());
        newinfo.setName(cainfo.getName());
        caSession.editCA(roleMgmgToken, newinfo);
        ca = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getName());
        assertEquals("new description", ca.getDescription());
        
        // Remove
        CaTestUtils.removeCa(roleMgmgToken, testx509ca.getCAInfo());            
        assertNull("CA by name of " +  testx509ca.getName() + " shouldn't exist.", caTestSession.getCA(roleMgmgToken, testx509ca.getName()));
        assertNull("CA by name of " +   "TEST1" + " shouldn't exist.", caTestSession.getCA(roleMgmgToken,  "TEST1"));
      
    } 

    public void addAndGetCAWithDifferentCaid() throws Exception {
        cleanUpAnyExistingCa(testx509ca.getCAId(), testx509ca.getName());
        caSession.addCA(roleMgmgToken, testx509ca);
        CA ca1 = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        Certificate cert = testx509ca.getCACertificate();
        assertEquals(ca1.getCAId(), testx509ca.getCAId());
        // CA certificate subjectDN gives the correct caid here
        assertEquals(ca1.getCAId(), CertTools.getSubjectDN(cert).hashCode());
        // Now edit the CA to change the CA-certificate to something with a different subjectDN
        String cadn = "CN=TEST,O=Foo,C=SE";
        CAToken catoken = ca1.getCAToken();
        List<Certificate> cachain = new ArrayList<Certificate>();
        final PublicKey publicKey = cryptoTokenManagementProxySession.getPublicKey(catoken.getCryptoTokenId(), catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)).getPublicKey();
        final PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(catoken.getCryptoTokenId(), catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", privateKey, publicKey, "SHA256WithRSA", true, cryptoTokenManagementProxySession.getSignProviderName(catoken.getCryptoTokenId()));
        assertNotNull(cacert);
        cachain.add(cacert);
        CAInfo cainfo = ca1.getCAInfo();
        cainfo.setCertificateChain(cachain);
        caSession.editCA(roleMgmgToken, cainfo);
        // Now get the CA and verify that the certificate was changed
        CA ca2 = (CA)caTestSession.getCA(roleMgmgToken, testx509ca.getCAId());
        Certificate cert2 = ca2.getCACertificate();
        assertEquals(ca2.getCAId(), testx509ca.getCAId());
        // CA certificate subjectDN gives the correct caid here
        int certcaid = CertTools.getSubjectDN(cert2).hashCode();
        assertFalse("CAIds should be different using new CA certifciate", ca2.getCAId() == certcaid);
        // See if we can get the CA using the "bad" ca id as well
        // First time should find it, and it should add an entry to the "cache" of CAIds in CaSessionBean
        // Second time uses this cache, therefore we will try two times to make sure that both lookup and cache works
        CA ca3 = (CA)caTestSession.getCA(roleMgmgToken, certcaid);
        assertNotNull(ca3);
        assertEquals(ca3.getCAId(), testx509ca.getCAId());
        CA ca4 = (CA)caTestSession.getCA(roleMgmgToken, certcaid);
        assertNotNull(ca4);
        assertEquals(ca4.getCAId(), testx509ca.getCAId());
    } // testAddAndGetCAWithDifferentCaid

    /**
     * Add CA object first with just key references and let these references sign the initial CA certificate.
     * This probably works due to the lack of sanity checks (like that a CA probably should have a CA certificate).
     * @param ca a CA that is expected to be added to the system with a crypto token (caSession.addCA must have been done, the caller is responsible for cleaning up the CA and Crypto Token
     * @param tokenpwd the password for activating the CAs crypto token and generating keys 
     */
    protected void addCAGenerateKeysLater(CA ca, char[] tokenpwd) throws Exception {
    	X509Certificate cert = null;
    	try {
        	// Generate keys, will audit log
        	int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
        	cryptoTokenManagementSession.activate(roleMgmgToken, cryptoTokenId, tokenpwd);
        	final String signKeyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
        	cryptoTokenManagementSession.createKeyPair(roleMgmgToken, cryptoTokenId, signKeyAlias, KeyGenParams.builder("RSA1024").build());
        	// Now create a CA certificate
        	CAInfo info = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
            // We need the CA public key, since we activated the newly generated key, we know that it has a key purpose now
        	PublicKey pk = cryptoTokenManagementSession.getPublicKey(roleMgmgToken, cryptoTokenId, signKeyAlias).getPublicKey();
            EndEntityInformation user = new EndEntityInformation("casessiontestca", ca.getSubjectDN(), ca.getCAId(), null, null, new EndEntityType(EndEntityTypes.ENDUSER), 0,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");
        	SimpleRequestMessage req = new SimpleRequestMessage(pk, user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            cert = (X509Certificate)resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            // Verifies with CA token?
            cert.verify(pk);
            // Add the new CA cert
            List<Certificate> certs = info.getCertificateChain(); 
            assertEquals(0, certs.size());
            certs.add(cert);
            info.setCertificateChain(certs);
            caSession.editCA(roleMgmgToken, info);
            
            // Get it again
            CAInfo info1 = caSession.getCAInfo(roleMgmgToken, ca.getCAId());
        	Collection<Certificate> certs1 = info1.getCertificateChain(); 
        	assertEquals(1, certs1.size());
        	Certificate cert1 = certs1.iterator().next();
            cert1.verify(pk);
    	} finally {
            // Since this could be a P11 slot, we need to clean up the actual keys in the slot, not just delete the token
    	    // So delete the keys we have generated above at least
            int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            final String signKeyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            if (cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, signKeyAlias)) {
                cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, signKeyAlias);
            }
    	}    	
    }
    
    /**
     * Add CA object first with just key references and let these references sign the initial CA certificate.
     * This probably works due to the lack of sanity checks (like that a CA probably should have a CA certificate).
     * @param ca a CA that is expected to be added to the system with a crypto token (caSession.addCA must have been done, the caller is responsible for cleaning up the CA and Crypto Token
     * @param tokenpwd the password for activating the CAs crypto token and generating keys 
     */
    protected void addCAUseSessionBeanToGenerateKeys(CA ca, char[] tokenpwd) throws Exception {        
        AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken("addCAUseSessionBeanToGenerateKeys");
        Certificate cert = null;
        try {
            CAToken caToken = ca.getCAToken();
            caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, "signKeyAlias");
            caToken.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, "signKeyAlias");
            ca.setCAToken(caToken);
            caSession.editCA(authenticationToken, ca.getCAInfo());
            final int cryptoTokenId = caToken.getCryptoTokenId();
            // Generate CA keys
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, "signKeyAlias", KeyGenParams.builder("RSA1024").build());
            PublicKey pubK = cryptoTokenManagementSession.getPublicKey(authenticationToken, cryptoTokenId, "signKeyAlias").getPublicKey();
            assertNotNull(pubK);
            // Now create a CA certificate
            CAInfo info = caSession.getCAInfo(authenticationToken, ca.getCAId());
            List<Certificate> certs = info.getCertificateChain();
            assertEquals(0, certs.size());

            EndEntityInformation user = new EndEntityInformation("casessiontestca", ca.getSubjectDN(), ca.getCAId(), null, null, new EndEntityType(
                    EndEntityTypes.ENDUSER), 0, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, EndEntityConstants.TOKEN_USERGEN, null);
            user.setStatus(EndEntityConstants.STATUS_NEW);
            user.setPassword("foo123");
            SimpleRequestMessage req = new SimpleRequestMessage(pubK, user.getUsername(), user.getPassword());
            X509ResponseMessage resp = (X509ResponseMessage) certificateCreateSession.createCertificate(authenticationToken, user, req,
                    org.cesecore.certificates.certificate.request.X509ResponseMessage.class, signSession.fetchCertGenParams());
            cert = resp.getCertificate();
            assertNotNull("Failed to create certificate", cert);
            // Verifies with CA token?
            cert.verify(pubK);
            // Add the new CA cert
            certs.add(cert);
            info.setCertificateChain(certs);
            caSession.editCA(authenticationToken, info);

            // Get it again
            CAInfo info1 = caSession.getCAInfo(authenticationToken, ca.getCAId());
            Collection<Certificate> certs1 = info1.getCertificateChain();
            assertEquals(1, certs1.size());
            Certificate cert1 = certs1.iterator().next();
            cert1.verify(pubK);
        } finally {
            // Since this could be a P11 slot, we need to clean up the actual keys in the slot, not just delete the token
            // So delete the keys we have generated above at least
            int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            final String signKeyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
            if (cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, signKeyAlias)) {
                cryptoTokenManagementSession.removeKeyPair(alwaysAllowToken, cryptoTokenId, signKeyAlias);
            }
        }       
    }



    /** 
     * @param ca CA to test extended CA services on, the CA must be cleaned up/removed by caller, including the crypto token
     */
    protected void extendedCAServices(CA ca) throws Exception {
        cleanUpAnyExistingCa(ca.getCAId(), null);
        // Generate CA keys
        caSession.addCA(roleMgmgToken, ca);
        final String caName = ca.getName();
        CAInfo cainfo = caSession.getCAInfo(roleMgmgToken, caName);
        ArrayList<ExtendedCAServiceInfo> newlist = new ArrayList<ExtendedCAServiceInfo>();
        ExtendedCAServiceInfo myinfo = new TestExtendedCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE);
        newlist.add(myinfo);
        cainfo.setExtendedCAServiceInfos(newlist);
        caSession.editCA(roleMgmgToken, cainfo);
        cainfo = caSession.getCAInfo(roleMgmgToken, caName);
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
        cainfo = caSession.getCAInfo(roleMgmgToken, caName);
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
    }

    public void authorization() throws Exception {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA); 
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CaSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);
        cleanUpAnyExistingCa(testx509ca.getCAId(), null);
        // Try to add and edit CAs with and admin that does not have authorization
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
    }

    /** Remove any existing CA. Null value parameter can be used to ignore one of the alternatives. */
    protected void cleanUpAnyExistingCa(Integer caId, String caname) throws AuthorizationDeniedException {
        // CaSessionTestBase depends on that the Crypto Token is not removed so it can be re-used.
        // a bad circular dependency
        if (caId != null) {
            caSession.removeCA(roleMgmgToken, caId.intValue());
        }
        if (caname != null) {
            final CAInfo caInfo = caSession.getCAInfo(roleMgmgToken, caname);
            if (caInfo != null) {
                caSession.removeCA(roleMgmgToken, caInfo.getCAId());
            }

        }
    }
    
}
