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

package org.ejbca.core.ejb.keyrecovery;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.util.KeyPairWrapper;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.util.GenerateToken;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the key recovery modules.
 * 
 * @version $Id$
 */
public class KeyRecoveryTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(KeyRecoveryTest.class);
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("KeyRecoveryTest"));
    private static final String user = genRandomUserName();

    private static final String KEYRECOVERY_ROLE = "KEYRECOVERYROLE";
    private static final String KEYRECOVERY_EEP = "TEST_KEYRECOVERY_EEP";
    private static final String TEST_EMAIL = "test@test.se";

    private static final KeyRecoverySessionRemote keyRecoverySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static final RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private static final RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private static final EndEntityAuthenticationSessionRemote endEntityAuthSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAuthenticationSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);

    private AuthenticationToken admin;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();

    }

    @Before
    public void setUp() throws Exception {
        super.setUp();
        admin = createCaAuthenticatedToken();

        RoleData role = roleManagementSession.create(internalAdmin, KEYRECOVERY_ROLE);
        Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        subjects.add(new AccessUserAspectData(KEYRECOVERY_ROLE, getTestCAId(), X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                CertTools.getPartFromDN(CertTools.getSubjectDN(getTestCACert()), "CN")));
        role = roleManagementSession.addSubjectsToRole(internalAdmin, role, subjects);
        Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, AccessRulesConstants.ENDENTITYPROFILEPREFIX + SecConst.EMPTY_ENDENTITYPROFILE
                + AccessRulesConstants.KEYRECOVERY_RIGHTS, AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRuleState.RULE_ACCEPT, true));
        role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, accessRules);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
        roleManagementSession.remove(internalAdmin, KEYRECOVERY_ROLE);

    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    /**
     * tests adding a keypair and checks if it can be read again, including rollover of the CAs keyEncryptKey and storing a second set of key recovery data.
     * 
     * @throws Exception error
     */
    @Test
    public void testAddAndRemoveKeyPairWithKeyRollOver() throws Exception {
        log.trace(">test01AddKeyPair()");
        // Generate test keypair and certificate.
        X509Certificate cert1 = null;
        X509Certificate cert2 = null;
        String fp1 = null;
        String fp2 = null;
        try {
            KeyPair keypair1 = null;
            try {
                if (!endEntityManagementSession.existsUser(user)) {
                    keypair1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                    endEntityManagementSession.addUser(internalAdmin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(), "rfc822name=" + TEST_EMAIL, TEST_EMAIL, false,
                            SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, 0,
                            getTestCAId());
                    cert1 = (X509Certificate) signSession.createCertificate(internalAdmin, user, "foo123", new PublicKeyWrapper(keypair1.getPublic()));
                    fp1 = CertTools.getFingerprintAsString(cert1);
                    Collection<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
                    accessRules.add(new AccessRuleData(KEYRECOVERY_ROLE, StandardRules.CAACCESS.resource() + CertTools.getIssuerDN(cert1).hashCode(), AccessRuleState.RULE_ACCEPT, false));
                    roleManagementSession.addAccessRulesToRole(internalAdmin, roleAccessSession.findRole(KEYRECOVERY_ROLE), accessRules);
                }
            } catch (Exception e) {
                log.error("Exception generating keys/cert: ", e);
                fail("Exception generating keys/cert");
            }
            if(!keyRecoverySession.addKeyRecoveryData(internalAdmin, cert1, user, new KeyPairWrapper(keypair1))) {
                throw new RuntimeException("Key recovery data already exists in database.");
            }
            assertTrue("Couldn't save key's in database", keyRecoverySession.existsKeys(cert1));
            log.trace("<test01AddKeyPair()");
            log.trace(">test02MarkAndRecoverKeyPair()");
            assertFalse("User should not be marked for recovery in database", keyRecoverySession.isUserMarked(user));
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            KeyRecoveryInformation data = keyRecoverySession.recoverKeys(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair1.getPrivate().getEncoded()));
            log.trace("<test02MarkAndRecoverKeyPair()");
            
            log.trace(">test03KeyEncryptKeyRollOver()");
            // So we have successfully stored and retrieved key recovery data for a user. 
            // Lets move on to something more advanced, changing the CAs keys used to protect the key recovery data
            // Generate a new key on CA crypto token
            final CAInfo cainfo = caSession.getCAInfo(internalAdmin, getTestCAId());
            final String currentAlias = cainfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
            final String nextAlias = "keyRecoveryTestKey";
            final int cryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.createKeyPairWithSameKeySpec(internalAdmin, cryptoTokenId, currentAlias, nextAlias);
            // Switch keyEncryptKey of the CAToken to the new key
            cainfo.getCAToken().setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, nextAlias);
            caSession.editCA(internalAdmin, cainfo);
            // Store a new key pair as key recovery data for the same user (check value of keyAlias column)
            KeyPair keypair2 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            EndEntityInformation ei = eeAccessSession.findUser(internalAdmin, user);
            ei.setPassword("foo123");
            endEntityManagementSession.changeUser(internalAdmin, ei, false);
            cert2 = (X509Certificate) signSession.createCertificate(internalAdmin, user, "foo123", new PublicKeyWrapper(keypair2.getPublic()));
            fp2 = CertTools.getFingerprintAsString(cert2);
            keyRecoverySession.addKeyRecoveryData(internalAdmin, cert2, user, new KeyPairWrapper(keypair2));
            // Recover the first (old) key pair
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);
            // If we hadn't stored the actual key alias that was used to protect a specific entry, this is where we would fail
            // since we have changed the "keyEncryptKey" of the CA by now, so that key can not recover this old key pair.
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair1.getPrivate().getEncoded()));
            keyRecoverySession.unmarkUser(admin, user);
            // Recover the new key pair 
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert2);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair2.getPrivate().getEncoded()));
            keyRecoverySession.unmarkUser(admin, user);
            // Now that worked, lets say we remove the first key that was used to protect data once in a time
            // Delete the RSA key that was used before as keyEncryptKey
            cryptoTokenManagementSession.removeKeyPair(internalAdmin, cryptoTokenId, currentAlias);
            // Try to recover the first (old) key pair, this should not work without that old keyEncryptKey
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);
            assertNull("Could recover keys from database although we should not", data);
            keyRecoverySession.unmarkUser(admin, user);
            // Recover the new key pair, this should still work
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, SecConst.EMPTY_ENDENTITYPROFILE, cert2);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, SecConst.EMPTY_ENDENTITYPROFILE);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair2.getPrivate().getEncoded()));
            // Even that worked as expected if we came all the way here, great success!
            log.trace("<test03KeyEncryptKeyRollOver()");            
        } finally {
            // Only clean up left.
            log.trace(">test04RemoveKeyPairAndEntity()");
            if (cert1 != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, cert1);
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(cert1));
            }
            if (cert2 != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, cert2);
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(cert2));
            }
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
            endEntityManagementSession.deleteUser(internalAdmin, user);
            log.trace("<test04RemoveKeyPairAndEntity()");
        }
    }
    
    /**
     * Test that uses CertificateRequestSession for key recovery.
     * During the test the end-entity CA is changed, which should not cause any problems.
     */
    @Test
    public void testRecoveryUsingCertificateRequestSession() throws Exception {
        log.trace(">testRecoveryWithChangedCA");
        final String testuser = genRandomUserName();
        final String TESTCA1 = "TESTKEYRECCA1";
        final String TESTCA2 = "TESTKEYRECCA2";
        X509Certificate usercert = null;
        String fp1 = null;
        try {
            // Create two CAs
            createTestCA(TESTCA1);
            createTestCA(TESTCA2);
            final int caId1 = caSession.getCAInfo(internalAdmin, TESTCA1).getCAId();
            final int caId2 = caSession.getCAInfo(internalAdmin, TESTCA2).getCAId();
            
            // Create a new end-entity profile with key recovery enabled with the "reuse old certificate" option
            final Collection<Integer> availcas = new ArrayList<Integer>();
            availcas.add(caId1);
            availcas.add(caId2);
            final EndEntityProfile eeprofile = new EndEntityProfile();
            eeprofile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
            eeprofile.setReUseKeyRecoveredCertificate(true);
            eeprofile.setAvailableCAs(availcas);
            endEntityProfileSession.addEndEntityProfile(internalAdmin, KEYRECOVERY_EEP, eeprofile);
            final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(KEYRECOVERY_EEP);
            
            // Create an end entity which is initially using CA 1
            EndEntityInformation eeinfo = new EndEntityInformation(testuser, "CN=TEST_KEYREC_CACHANGE" + new Random(),
                    caId1, "", null, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    eeProfileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    new Date(), new Date(), SecConst.TOKEN_SOFT_P12, SecConst.NO_HARDTOKENISSUER, null);
            eeinfo.setPassword("foo123");
            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, testuser, "foo123");
            
            // Issue a certifiate + keystore
            eeinfo = eeAccessSession.findUser(internalAdmin, testuser);
            assertNotNull("Could not find test user", testuser);
            eeinfo.setPassword("foo123");
            final GenerateToken tgen1 = new GenerateToken(endEntityAuthSession, eeAccessSession, endEntityManagementSession, caSession, keyRecoverySession, signSession);
            final KeyStore ks1 = tgen1.generateOrKeyRecoverToken(internalAdmin, testuser, "foo123", caId1, "1024", AlgorithmConstants.KEYALGORITHM_RSA, false, false, true, eeprofile.getReUseKeyRecoveredCertificate(), eeProfileId);
            usercert = (X509Certificate) certificateStoreSession.findCertificatesByUsername(testuser).get(0);
            fp1 = CertTools.getFingerprintAsString(usercert);
            assertNotNull("Could not find user's certificate in keystore", ks1.getCertificateAlias(usercert));
            
            // Now change the CA of the end-entity the CA 2
            eeinfo = eeAccessSession.findUser(internalAdmin, testuser);
            assertNotNull("Could not find test user", testuser);
            eeinfo.setCAId(caId2);
            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, testuser, "foo123");
            
            // Now try to perform key recovery
            assertTrue("markAsRecoverable failed", keyRecoverySession.markAsRecoverable(internalAdmin, usercert, eeProfileId));
            final GenerateToken tgen2 = new GenerateToken(endEntityAuthSession, eeAccessSession, endEntityManagementSession, caSession, keyRecoverySession, signSession);
            final KeyStore ks2 = tgen2.generateOrKeyRecoverToken(internalAdmin, testuser, "foo123", caId2, "1024", AlgorithmConstants.KEYALGORITHM_RSA, false, true, false, eeprofile.getReUseKeyRecoveredCertificate(), eeProfileId);
            assertFalse("Users should have been unmarked for key recovery", keyRecoverySession.isUserMarked(testuser));
            
            // Certificate should not have changed
            assertNotNull("Could not find user's certificate in key-recovered keystore", ks2.getCertificateAlias(usercert));
        } finally {
            if (usercert != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, usercert);
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(usercert));
            }
            if (fp1 != null) {
                internalCertStoreSession.removeCertificate(fp1);
            }
            if (endEntityManagementSession.existsUser(testuser)) {
                endEntityManagementSession.deleteUser(internalAdmin, testuser);
            }
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, KEYRECOVERY_EEP);
            removeOldCa(TESTCA1);
            removeOldCa(TESTCA2);
            log.trace("<testRecoveryWithChangedCA");
        }
    }
}
