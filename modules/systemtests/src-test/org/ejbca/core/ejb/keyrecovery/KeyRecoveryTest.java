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

import java.io.ByteArrayInputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.GlobalConfigurationProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.KeyStoreCreateSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

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
    private static final KeyStoreCreateSessionRemote keyStoreCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyStoreCreateSessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private static final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private static final EndEntityAccessSessionRemote eeAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
    private static final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private static final GlobalConfigurationProxySessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private AuthenticationToken admin;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        admin = createCaAuthenticatedToken();
        final Role role = roleSession.persistRole(internalAdmin, new Role(null, KEYRECOVERY_ROLE, Arrays.asList(
                AccessRulesConstants.ENDENTITYPROFILEPREFIX + EndEntityConstants.EMPTY_END_ENTITY_PROFILE + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                AccessRulesConstants.REGULAR_KEYRECOVERY,
                StandardRules.CAACCESS.resource() + getTestCAId()
                ), null));
        roleMemberSession.persist(internalAdmin, new RoleMember(X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, getTestCAId(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                CertTools.getPartFromDN(CertTools.getSubjectDN(getTestCACert()), "CN"), role.getRoleId(), null));
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        final Role role = roleSession.getRole(internalAdmin, null, KEYRECOVERY_ROLE);
        if (role!=null) {
            roleSession.deleteRoleIdempotent(internalAdmin, role.getRoleId());
        }
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    /**
     * tests adding a keypair and checks if it can be read again, including rollover of the CAs keyEncryptKey and storing a second set of key recovery data.
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
                            EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12,
                            getTestCAId());
                    cert1 = (X509Certificate) signSession.createCertificate(internalAdmin, user, "foo123", new PublicKeyWrapper(keypair1.getPublic()));
                    fp1 = CertTools.getFingerprintAsString(cert1);
                }
            } catch (Exception e) {
                log.error("Exception generating keys/cert: ", e);
                fail("Exception generating keys/cert");
            }
            assertTrue("Key recovery data already exists in database.", keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1), user, EJBTools.wrap(keypair1)));
            assertTrue("Couldn't save keys in database", keyRecoverySession.existsKeys(EJBTools.wrap(cert1)));
            // Try again, now it exists and should return 
            assertFalse("Key recovery data already exists in database, but adding return true instead of false.", keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1), user, EJBTools.wrap(keypair1)));
            log.trace("<test01AddKeyPair()");
            log.trace(">test02MarkAndRecoverKeyPair()");
            assertFalse("User should not be marked for recovery in database", keyRecoverySession.isUserMarked(user));
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            KeyRecoveryInformation data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
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
            keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert2), user, EJBTools.wrap(keypair2));
            // Recover the first (old) key pair
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            // If we hadn't stored the actual key alias that was used to protect a specific entry, this is where we would fail
            // since we have changed the "keyEncryptKey" of the CA by now, so that key can not recover this old key pair.
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair1.getPrivate().getEncoded()));
            keyRecoverySession.unmarkUser(admin, user);
            // Recover the new key pair 
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert2);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            assertNotNull("Couldn't recover keys from database", data);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair2.getPrivate().getEncoded()));
            keyRecoverySession.unmarkUser(admin, user);
            // Now that worked, lets say we remove the first key that was used to protect data once in a time
            // Delete the RSA key that was used before as keyEncryptKey
            cryptoTokenManagementSession.removeKeyPair(internalAdmin, cryptoTokenId, currentAlias);
            // Try to recover the first (old) key pair, this should not work without that old keyEncryptKey
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert1);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            assertNull("Could recover keys from database although we should not", data);
            keyRecoverySession.unmarkUser(admin, user);
            // Recover the new key pair, this should still work
            endEntityManagementSession.prepareForKeyRecovery(internalAdmin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert2);
            assertTrue("Couldn't mark user for recovery in database", keyRecoverySession.isUserMarked(user));
            data = keyRecoverySession.recoverKeys(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
            assertTrue("Couldn't recover keys from database",
                    Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair2.getPrivate().getEncoded()));
            // Even that worked as expected if we came all the way here, great success!
            log.trace("<test03KeyEncryptKeyRollOver()");            
        } finally {
            // Only clean up left.
            log.trace(">test04RemoveKeyPairAndEntity()");
            if (cert1 != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1));
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(EJBTools.wrap(cert1)));
            }
            if (cert2 != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(cert2));
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(EJBTools.wrap(cert2)));
            }
            internalCertStoreSession.removeCertificate(fp1);
            internalCertStoreSession.removeCertificate(fp2);
            endEntityManagementSession.deleteUser(internalAdmin, user);
            log.trace("<test04RemoveKeyPairAndEntity()");
        }
    }
    
    /**
     * Tests the authorization rights required to mark an end entity for key recovery. Proper rights should be:
     * 
     * /ra_functionality/keyrecovery
     * /endentityprofilesrules/<x>/keyrecovery
     * /ca/<y>
     * 
     * where <x> is the EEP for the end entity, and <y> is the CA ID for the issuing CA. 
     * @throws CADoesntExistsException 
     */
    @Test
    public void testAuthorizationForKeyRecovery()
            throws ApprovalException, WaitingForApprovalException, AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException, CADoesntExistsException {
        X509Certificate cert1 = null;
        String fp1 = null;
        KeyPair keypair1 = null;
        try {
            if (!endEntityManagementSession.existsUser(user)) {
                try {
                    keypair1 = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
                    endEntityManagementSession.addUser(internalAdmin, user, "foo123", "CN=TESTKEYREC" + new Random().nextLong(),
                            "rfc822name=" + TEST_EMAIL, TEST_EMAIL, false, EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_P12, getTestCAId());
                    cert1 = (X509Certificate) signSession.createCertificate(internalAdmin, user, "foo123",
                            new PublicKeyWrapper(keypair1.getPublic()));
                    fp1 = CertTools.getFingerprintAsString(cert1);
                } catch (InvalidAlgorithmParameterException | CADoesntExistsException | EndEntityExistsException | AuthorizationDeniedException
                        | EndEntityProfileValidationException | EjbcaException | NoSuchEndEntityException | IllegalKeyException
                        | CertificateCreateException | IllegalNameException | CertificateRevokeException | CertificateSerialNumberException
                        | CryptoTokenOfflineException | IllegalValidityException | CAOfflineException | InvalidAlgorithmException
                        | CustomCertificateSerialNumberException e) {
                    throw new IllegalStateException("Exception generating keys/cert", e);
                }
            }
            if (!keyRecoverySession.addKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1), user, EJBTools.wrap(keypair1))) {
                throw new IllegalStateException("Key recovery data already exists in database.");
            }
            if (!keyRecoverySession.existsKeys(EJBTools.wrap(cert1))) {
                throw new IllegalStateException("Couldn't save key's in database");
            }
            if (keyRecoverySession.isUserMarked(user)) {
                throw new IllegalStateException("User should not be marked for recovery in database");

            }
            try {
                endEntityManagementSession.prepareForKeyRecovery(admin, user, EndEntityConstants.EMPTY_END_ENTITY_PROFILE, cert1);
            } catch (AuthorizationDeniedException e) {
                fail("Key recovery could not be performed due to incorrect authorization checks.");
            }
        } finally {
            internalCertStoreSession.removeCertificate(fp1);
            endEntityManagementSession.deleteUser(internalAdmin, user);
            keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(cert1));
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
            EndEntityInformation eeinfo = new EndEntityInformation(testuser, "CN=TEST_KEYREC_CACHANGE" + new Random().nextLong(),
                    caId1, "", null, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    eeProfileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword("foo123");
            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, testuser, "foo123");
            
            // Issue a certifiate + keystore
            eeinfo = eeAccessSession.findUser(internalAdmin, testuser);
            assertNotNull("Could not find test user", testuser);
            eeinfo.setPassword("foo123");
            boolean createJKS = false;
            final byte[] ks1 = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, testuser, "foo123", caId1, "1024", AlgorithmConstants.KEYALGORITHM_RSA, createJKS, false, true, eeprofile.getReUseKeyRecoveredCertificate(), eeProfileId);
            KeyStore keystore1 = KeyStore.getInstance(createJKS?"JKS":"PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore1.load(new ByteArrayInputStream(ks1), "foo123".toCharArray());
            usercert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(testuser)).get(0);
            fp1 = CertTools.getFingerprintAsString(usercert);
            assertNotNull("Could not find user's certificate in keystore", keystore1.getCertificateAlias(usercert));
            
            // Now change the CA of the end-entity the CA 2
            eeinfo = eeAccessSession.findUser(internalAdmin, testuser);
            assertNotNull("Could not find test user", testuser);
            eeinfo.setCAId(caId2);
            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, testuser, "foo123");
            
            // Now try to perform key recovery
            assertTrue("markAsRecoverable failed",endEntityManagementSession.prepareForKeyRecovery(internalAdmin, testuser, eeProfileId, usercert));
            final byte[] ks2 = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, testuser, "foo123", caId2, "1024", AlgorithmConstants.KEYALGORITHM_RSA, createJKS, true, false, eeprofile.getReUseKeyRecoveredCertificate(), eeProfileId);
            KeyStore keystore2 = KeyStore.getInstance(createJKS?"JKS":"PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            keystore2.load(new ByteArrayInputStream(ks2), "foo123".toCharArray());
            assertFalse("Users should have been unmarked for key recovery", keyRecoverySession.isUserMarked(testuser));
            
            // Certificate should not have changed
            assertNotNull("Could not find user's certificate in key-recovered keystore", keystore2.getCertificateAlias(usercert));
        } finally {
            if (usercert != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(usercert));
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(EJBTools.wrap(usercert)));
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
    
    /**
     * Tests generation or recovery of keystores for an existing user.
     */
    @Test
    public void testGenerateOrRecoverKeystore() throws Exception {
        log.trace(">testGenerateOrRecoverKeystore");
        final String eeProfileName = "TEST_PKCS12_REQ_WS";
        final String username = "testUserForPkcs12";
        final String password = "foo123";
        final String testCaName = "TESTPKCS12CA";
        X509Certificate usercert = null;
        final String format = "PKCS12";
        String fingerprint = null;
        try {
            setGlobalConfigurationEnableKeyRecovery(true);

            // Create test CA.
            createTestCA(testCaName);
            final int caId = caSession.getCAInfo(internalAdmin, testCaName).getCAId();
            
            // Create a new end-entity profile with key recovery enabled with the "reuse old certificate" option
            Collection<Integer> availcas = new ArrayList<Integer>();
            availcas.add(caId);
            final EndEntityProfile eeprofile = new EndEntityProfile();
            eeprofile.setUse(EndEntityProfile.KEYRECOVERABLE, 0, true);
            eeprofile.setReUseKeyRecoveredCertificate(true);
            eeprofile.setAvailableCAs(availcas);
            endEntityProfileSession.addEndEntityProfile(internalAdmin, eeProfileName, eeprofile);
            final int eeProfileId = endEntityProfileSession.getEndEntityProfileId(eeProfileName);
            
            // Create an end entity.
            EndEntityInformation eeinfo = new EndEntityInformation(username, "CN=" + username,
                    caId, "", null, EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    eeProfileId, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                    new Date(), new Date(), SecConst.TOKEN_SOFT_P12, null);
            eeinfo.setPassword(password);
            eeinfo.setKeyRecoverable(true);
            endEntityManagementSession.addUser(internalAdmin, eeinfo, false);
            endEntityManagementSession.setPassword(internalAdmin, username, password);
            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
            
            // 1. Create or recover keystores.
            // 1.1 Create new keystore and issue a certificate.
            eeinfo = eeAccessSession.findUser(internalAdmin, username);
            assertNotNull("Could not find test user", username);
            // eeinfo.setPassword("foo123");
            byte[] keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, password, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
            KeyStore keystore = KeyStore.getInstance(format, BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(keystoreBytes), password.toCharArray());
            usercert = (X509Certificate) EJBTools.unwrapCertCollection(certificateStoreSession.findCertificatesByUsername(username)).get(0);
            fingerprint = CertTools.getFingerprintAsString(usercert);
            assertNotNull("Could not find user's certificate in keystore", keystore.getCertificateAlias(usercert));
            
            // 1.2 Recover keystore and certificate.
            eeinfo = eeAccessSession.findUser(internalAdmin, username);
//            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
//            endEntityManagementSession.setPassword(internalAdmin, username, password);
            
            assertTrue("markAsRecoverable failed",endEntityManagementSession.prepareForKeyRecovery(internalAdmin, username, eeProfileId, usercert));
            // Generate keystore.
            keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, password, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
            keystore = KeyStore.getInstance(format, BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(keystoreBytes), password.toCharArray());
            assertFalse("Users should have been unmarked for key recovery", keyRecoverySession.isUserMarked(username));
            // Certificate should not have changed
            assertNotNull("Could not find user's certificate in key-recovered keystore", keystore.getCertificateAlias(usercert));
            
            // 1.3 Recover keystore and issue new certificate.
            eeinfo = eeAccessSession.findUser(internalAdmin, username);
            endEntityManagementSession.setPassword(internalAdmin, username, password);
            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
            // Configure EEP.
            eeprofile.setReUseKeyRecoveredCertificate(false);
            endEntityProfileSession.changeEndEntityProfile(internalAdmin, eeProfileName, eeprofile);
            assertTrue("markAsRecoverable failed",endEntityManagementSession.prepareForKeyRecovery(internalAdmin, username, eeProfileId, usercert));
            // Generate keystore.
            keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, password, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
            keystore = KeyStore.getInstance(format, BouncyCastleProvider.PROVIDER_NAME);
            keystore.load(new ByteArrayInputStream(keystoreBytes), password.toCharArray());
            assertFalse("Users should have been unmarked for key recovery", keyRecoverySession.isUserMarked(username));
            // Certificate should not have changed
            assertNull("Could not find user's certificate in key-recovered keystore", keystore.getCertificateAlias(usercert));
            
            // 2. Test error / exception handling.
            // 2.1 Test user not found.
            eeinfo.setStatus(EndEntityConstants.STATUS_NEW);
            endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
            try {
                final String notExistingUsername = username + "_NOT_EXISTS";
                assertFalse("This user should not exists: " + notExistingUsername, endEntityManagementSession.existsUser(notExistingUsername));
                keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username + notExistingUsername, password, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                fail("Requesting a key recovery for a non existing user should throw an exception.");
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("NotFoundException expected!: ", e);
                }
                assertTrue("Requesting a key recovery for a non existing user should throw a NotFoundException.", e instanceof NotFoundException);
            }
            // 2.2 Test wrong password.
            try {
                keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, password + "_not_exists", "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                fail("Requesting a key recovery for a wrong user/password combination should throw an exception.");
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("AuthLoginException expected!: ", e);
                }
                assertTrue("Requesting a key recovery for a wrong user/password combination should throw an AuthLoginException.", e instanceof AuthLoginException);
            }
            // 2.3 Test CA not found.
//            try {
//                final int nonExistingCaId = 1123243;
//                assertNull("This CA should not exist.", caSession.getCAInfo(internalAdmin, nonExistingCaId));
//                availcas = new ArrayList<Integer>();
//                availcas.add(nonExistingCaId);
//                eeprofile.setAvailableCAs(availcas);
//                endEntityProfileSession.changeEndEntityProfile(internalAdmin, eeProfileName, eeprofile);
//                eeinfo.setCAId(nonExistingCaId);
//                endEntityManagementSession.setPassword(internalAdmin, username, password);
//                // Breaks here because of a NPE for the non existing CA.
//                endEntityManagementSession.changeUser(internalAdmin, eeinfo, false);
//                eeinfo = eeAccessSession.findUser(internalAdmin, username);
//                keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(internalAdmin, username, password, hardTokenSN, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
//                fail("Requesting a key recovery for a non existing CA should throw an exception.");
//            } catch (Exception e) {
//                if (log.isDebugEnabled()) {
//                    log.debug("CADoesntExistsException expected!: ", e);
//                }
//                assertTrue("Requesting a key recovery for a non existing CA should throw a CADoesntExistsException.", e instanceof CADoesntExistsException);
//            }
            // 2.4 Test CA no authorization for CA.
            try {
                keystoreBytes = keyStoreCreateSession.generateOrKeyRecoverTokenAsByteArray(admin, username, password, "1024", AlgorithmConstants.KEYALGORITHM_RSA);
                fail("Requesting a key recovery for a CA with no authorization should throw an exception.");
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("AuthorizationDeniedException expected!: ", e);
                }
                assertTrue("Requesting a key recovery for a CA with no authorization should throw an AuthorizationDeniedException.", e instanceof AuthorizationDeniedException);
            }
        } finally {
            setGlobalConfigurationEnableKeyRecovery(false);
            if (usercert != null) {
                keyRecoverySession.removeKeyRecoveryData(internalAdmin, EJBTools.wrap(usercert));
                assertTrue("Couldn't remove keys from database", !keyRecoverySession.existsKeys(EJBTools.wrap(usercert)));
            }
            if (fingerprint != null) {
                internalCertStoreSession.removeCertificate(fingerprint);
            }
            if (endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.deleteUser(internalAdmin, username);
            }
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, eeProfileName);
            removeOldCa(testCaName);
            log.trace("<testGenerateOrRecoverKeystore");
        }
    }
    
    private void setGlobalConfigurationEnableKeyRecovery(final boolean enabled) throws AuthorizationDeniedException {
        final GlobalConfiguration globalConfig = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        globalConfig.setEnableKeyRecovery(enabled);
        globalConfigurationSession.saveConfiguration(internalAdmin, globalConfig);
    }
}
