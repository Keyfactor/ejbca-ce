/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.io.StreamCorruptedException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Key validator session.
 * 
 * @version $Id: KeyValidatorSessionTest.java 25500 2017-04-01 11:28:08Z anjakobs $
 */
public class KeyValidatorSessionTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(KeyValidatorSessionTest.class);

    /** Test user. */
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(
            new UsernamePrincipal("KeyValidatorSessionTest-Admin"));

    private static final String TEST_CA_NAME = "KeyValidatorSessionTest-TestCA";

    private static final String TEST_CP_NAME = "KeyValidatorSessionTest-TestCP";

    private static final String TEST_EEP_NAME = "KeyValidatorSessionTest-TestEEP";

    private static final String TEST_EE_NAME = "KeyValidatorSessionTest-TestEE";

    private static final String TEST_EE_PASSWORD = "start#123";

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CertificateProfileSessionRemote.class);

    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private EndEntityManagementSessionRemote endEntityManagementSessionRemote = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);

    private KeyValidatorProxySessionRemote keyValidatorProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    // Helper objects.
    protected X509CA testCA;

    protected CertificateProfile testCertificateProfile;

    protected EndEntityProfile testEndEntityProfile;

    protected EndEntityInformation testUser;

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        // Create test CAs.
        removeCAIfExist(TEST_CP_NAME);
        testCA = CaTestUtils.createTestX509CA("CN=" + TEST_CA_NAME, null, false);
        caSession.addCA(internalAdmin, testCA);
        final X509CAInfo caInfo = (X509CAInfo) caSession.getCAInfo(internalAdmin, TEST_CA_NAME);
        testCA = new X509CA(caInfo);
        assertNotNull(testCA);
        if (log.isDebugEnabled()) {
            log.debug("Test CA " + testCA.getName() + " with DN " + testCA.getSubjectDN() + " and id " + testCA.getCAId() + " created.");
        }
        // Create test CPs.
        removeCertificateProfileIfExist(TEST_CP_NAME);
        testCertificateProfile = createTestCertificateProfile(TEST_CP_NAME);

        // Create test EEP.
        removeEndEntityProfileIfExist(TEST_EEP_NAME);
        testEndEntityProfile = createTestEndEntityProfile(TEST_EEP_NAME);

        // Create test user.
        removeUserIfExists(TEST_EE_NAME);
        testUser = createTestEndEntity(TEST_EE_NAME);

        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        removeUserIfExists(TEST_EE_NAME);
        removeEndEntityProfileIfExist(TEST_EEP_NAME);
        removeCertificateProfileIfExist(TEST_CP_NAME);
        CaTestUtils.removeCa(internalAdmin, testCA.getCAInfo());
        log.trace("<tearDown()");
    }

    @Test
    public void test01AddChangeRemoveKeyValidators() throws Exception {
        log.trace(">test01AddChangeRemoveKeyValidators()");
        // Create some test data.
        final BaseKeyValidator rsaKeyValidatorDefault = createKeyValidator(RsaKeyValidator.KEY_VALIDATOR_TYPE, "rsa-test-1-default", null, null, -1,
                null, -1, -1);
        final BaseKeyValidator rsaKeyValidator = createKeyValidator(RsaKeyValidator.KEY_VALIDATOR_TYPE, "rsa-test-2", null, null, -1, null, -1, -1);
        ((RsaKeyValidator) rsaKeyValidator).setCABForumBaseLineRequirements142Settings();
        assertRsaKeyValidatorCABForumBaseLineRequirements142Values((RsaKeyValidator) rsaKeyValidator);

        final BaseKeyValidator eccKeyValidatorDefault = createKeyValidator(EccKeyValidator.KEY_VALIDATOR_TYPE, "ecc-test-1-default", null, null, -1,
                null, -1, -1);
        final BaseKeyValidator eccKeyValidator = createKeyValidator(EccKeyValidator.KEY_VALIDATOR_TYPE, "ecc-test-2", null, null, -1, null, -1, -1);
        ((EccKeyValidator) eccKeyValidator).setCABForumBaseLineRequirements142();
        assertEccKeyValidatorCABForumBaseLineRequirements142Values((EccKeyValidator) eccKeyValidator);

        final String[] allNames = new String[] { rsaKeyValidatorDefault.getName(), rsaKeyValidator.getName(), eccKeyValidatorDefault.getName(),
                eccKeyValidator.getName() };

        try {
            removeKeyValidatorsIfExist(rsaKeyValidatorDefault.getName(), rsaKeyValidator.getName(), eccKeyValidatorDefault.getName(),
                    eccKeyValidator.getName());

            // A: Add different new key validators.
            addKeyValidator(rsaKeyValidatorDefault);
            addKeyValidator(rsaKeyValidator);
            addKeyValidator(eccKeyValidatorDefault);
            addKeyValidator(eccKeyValidator);

            // A-1: Check add with defaults.
            // RSA key validator
            BaseKeyValidator keyValidator = keyValidatorProxySession.getKeyValidator(rsaKeyValidatorDefault.getName());
            assertKeyValidatorDefaultValues(keyValidator);
            // ECC key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(eccKeyValidatorDefault.getName());
            assertKeyValidatorDefaultValues(keyValidator);

            // A-2: Check change and load again with custom values.
            // RSA key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(rsaKeyValidatorDefault.getName());
            ((RsaKeyValidator) keyValidator).setCABForumBaseLineRequirements142Settings();
            keyValidatorProxySession.changeKeyValidator(internalAdmin, keyValidator.getName(), keyValidator);
            BaseKeyValidator testKeyValidator = keyValidatorProxySession.getKeyValidator(keyValidator.getName());
            assertEqualsBaseKeyValidator(keyValidator, testKeyValidator);
            assertRsaKeyValidatorCABForumBaseLineRequirements142Values((RsaKeyValidator) testKeyValidator);
            // ECC key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(eccKeyValidatorDefault.getName());
            ((EccKeyValidator) keyValidator).setCABForumBaseLineRequirements142();
            keyValidatorProxySession.changeKeyValidator(internalAdmin, keyValidator.getName(), keyValidator);
            testKeyValidator = keyValidatorProxySession.getKeyValidator(keyValidator.getName());
            assertEqualsBaseKeyValidator(keyValidator, testKeyValidator);
            assertEccKeyValidatorCABForumBaseLineRequirements142Values((EccKeyValidator) testKeyValidator);

            // A-3: Remove key validators.
            try {
                removeKeyValidatorsIfExist(allNames);
                assertKeyValidatorsNotExist(allNames);
            } catch (CouldNotRemoveKeyValidatorException e) {
                fail("Key validators have no references on other entities, so no exceptions should be thrown.");
            }
            assertKeyValidatorsNotExist(allNames);

            // Check Referential integrity: 
            // Add to test CA and try to remove it -> CouldNot RemoveKeyValidatorException expected.
            String name = "rsa-test-1-referential-integrity";
            removeKeyValidatorsIfExist(name);
            keyValidator = createKeyValidator(RsaKeyValidator.KEY_VALIDATOR_TYPE, name, null, null, -1, null, -1, -1);
            addKeyValidator(keyValidator);
            setKeyValidatorsForCa(testCA, keyValidator);
            try {
                keyValidatorProxySession.removeKeyValidator(internalAdmin, keyValidator.getName());
                assertKeyValidatorsExist(name);
                fail("Key validator with name " + name + " must not be removed because referential integrity.");
            } catch (CouldNotRemoveKeyValidatorException e) {
                setKeyValidatorsForCa(testCA);
                keyValidatorProxySession.removeKeyValidator(internalAdmin, keyValidator.getName());
                assertKeyValidatorsNotExist(name);
            }
        } finally {
            removeKeyValidatorsIfExist(allNames);
        }
        log.trace("<test01AddChangeRemoveKeyValidators()");
    }

    @Test
    public void test02ValidateRsaPublicKey() throws Exception {
        log.trace(">test02ValidateRsaPublicKey()");

        // A-1: Check validation of non RSA key, use ECC key instead -> KeyValidationIllegalKeyAlgorithmException expected.
        KeyPair keyPair = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA); // generateEcCurve("prime192v1");
        PublicKey publicKey = keyPair.getPublic();
        BaseKeyValidator keyValidator = createKeyValidator(RsaKeyValidator.KEY_VALIDATOR_TYPE, "rsa-test-1-default", null, null, -1, null, -1,
                KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex(), certificateProfileSession.getCertificateProfileId(TEST_CP_NAME));
        removeKeyValidatorsIfExist(keyValidator.getName());
        addKeyValidator(keyValidator);
        setKeyValidatorsForCa(testCA, keyValidator);
        try {
            keyValidatorProxySession.validatePublicKey(testCA, testUser, testCertificateProfile, new Date(new Date().getTime() - 1000 * 86400),
                    new Date(new Date().getTime() + 1000 * 86400), publicKey);
            fail("RSA key validator successfully validated an ECC key.");
        } catch (Exception e) {
            Assert.assertTrue("KeyValidationException expected when a RSA key validator tries to validate an ECC key: " + keyValidator.getName(),
                    e instanceof KeyValidationIllegalKeyAlgorithmException);
        }

        // B-1: Check valid RSA key -> issuance MUST be OK.
        keyPair = generateRsaKeyPair(2048); // KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        publicKey = keyPair.getPublic();
        try {
            final boolean result = keyValidatorProxySession.validatePublicKey(testCA, testUser, testCertificateProfile,
                    new Date(new Date().getTime() - 1000 * 86400), new Date(new Date().getTime() + 1000 * 86400), publicKey);
            Assert.assertTrue("2048 bit RSA key should validate with default settings.", result);
        } catch (EJBException e) {
            Assert.assertTrue(
                    "ECA-4219 Fix. BouncyCastle RSA keys cause java.io.StreamCorruptedException: Unexpected byte found when reading an object: 0, but another exception occured: "
                            + e.getCause(),
                    e.getCause() instanceof StreamCorruptedException);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            fail("2048 bit RSA key validation failed with default RSA key validator.");
        }

        // B-2: Check invalid RSA key with small key size and failed action 'Abort certificate issuance' -> issuance MUST be aborted.
        keyPair = generateRsaKeyPair(512); // KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        publicKey = keyPair.getPublic();
        try {
            final boolean result = keyValidatorProxySession.validatePublicKey(testCA, testUser, testCertificateProfile,
                    new Date(new Date().getTime() - 1000 * 86400), new Date(new Date().getTime() + 1000 * 86400), publicKey);
            Assert.assertFalse("512 bit RSA key should validate with default settings.", result);

        } catch (EJBException e) {
            Assert.assertTrue(
                    "ECA-4219 Fix. BouncyCastle RSA keys cause java.io.StreamCorruptedException: Unexpected byte found when reading an object: 0, but another exception occured: "
                            + e.getCause(),
                    e.getCause() instanceof StreamCorruptedException);
        } catch (Exception e) {
            log.error(e.getMessage(), e);
            fail("512 bit RSA key validation failed with default RSA key validator.");
        }

        // B-3: Check invalid RSA key with failed action NOT 'Abort certificate issuance' -> issuance SHOULD NOT be aborted.

        // Test server generated keys.
        //        KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

        log.trace("<test02ValidateRsaPublicKey()");
    }

    //    @Test
    //    public void test03ValidatePublicKey() throws Exception {
    //        log.trace(">test03ValidatePublicKey()");
    //
    //        // A: Validate different RSA Keys.
    //        // No key validator configured at all -> true
    //        KeyPair keyPairRsa = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
    //        log.info("TEST CA NAME: " + testCA.getName() + " " + testCA.getCAId());
    //        boolean result = keyValidatorProxySession.validatePublicKey(testCA, testUser, testCertificateProfile, new Date(),
    //                new Date(new Date().getTime() + 86400000), keyPairRsa.getPublic());
    //        Assert.assertTrue("Public key validation without any key validator defined should validate to true.", result);
    //
    //        log.trace("<test03ValidatePublicKey()");
    //    }

    /**
     * Test of the cache of publishers. This test depends on the default cache time of 1 second being used.
     * If you changed this config, publisher.cachetime, this test may fail. 
     */
    // ECA-4219 Impl. key validator cache test.
    //    @Test
    //    public void test02KeyValidatorCache() throws Exception {
    //        // First make sure we have the right cache time
    //        final String oldcachetime = configSession.getProperty("publisher.cachetime");
    //        configSession.updateProperty("publisher.cachetime", "1000");
    //        LdapPublisher publ = new LdapPublisher();
    //        publ.setDescription("foobar");
    //        final String name = KeyValidatorSessionTest.class.getSimpleName();
    //        try {
    //            // Add a publisher
    //            publisherProxySession.addPublisher(internalAdmin, name, publ);
    //            // Make sure publisher has the right value from the beginning
    //            BasePublisher pub = publisherSession.getPublisher(name);
    //            assertEquals("Description is not what we set", "foobar", pub.getDescription());
    //            // Change publisher
    //            pub.setDescription("bar");
    //            publisherSession.changePublisher(internalAdmin, name, pub);
    //            // Read publisher again, cache should have been updated directly
    //            pub = publisherSession.getPublisher(name);
    //            assertEquals("bar", pub.getDescription());
    //            // Flush caches to reset cache timeout
    //            publisherProxySession.flushPublisherCache();
    //            /// Read publisher to ensure it is in cache
    //            pub = publisherSession.getPublisher(name);
    //            assertEquals("bar", pub.getDescription());
    //            // Change publisher not flushing cache, old value should remain when reading
    //            pub.setDescription("newvalue");
    //            publisherProxySession.internalChangeCertificateProfileNoFlushCache(name, pub);
    //            pub = publisherSession.getPublisher(name);
    //            assertEquals("bar", pub.getDescription()); // old value
    //            // Wait 2 seconds and try again, now the cache should have been updated
    //            Thread.sleep(2000);
    //            pub = publisherSession.getPublisher(name);
    //            assertEquals("newvalue", pub.getDescription()); // new value
    //        } finally {
    //            configSession.updateProperty("publisher.cachetime", oldcachetime);
    //            publisherProxySession.removePublisher(internalAdmin, name);
    //        }
    //    }

    private void assertKeyValidatorsExist(String... names) {
        for (String name : names) {
            assertNotNull("Added key validator (name=" + name + ") must be retrieved by datastore. ", keyValidatorProxySession.getKeyValidator(name));
        }
    }

    private void assertKeyValidatorsNotExist(final String... names) {
        for (String name : names) {
            assertNull("Removed key validator must not be retrieved by datastore. ", keyValidatorProxySession.getKeyValidator(name));
        }
    }

    private void addKeyValidator(BaseKeyValidator keyValidator) throws AuthorizationDeniedException, KeyValidatorExistsException {
        keyValidatorProxySession.addKeyValidator(internalAdmin, keyValidator.getName(), keyValidator);
        assertKeyValidatorsExist(keyValidator.getName());
    }

    private void assertKeyValidatorDefaultValues(final BaseKeyValidator keyValidator) {
        assertBaseKeyValidatorDefaultValues(keyValidator);
        if (keyValidator instanceof RsaKeyValidator) {
            assertRsaKeyValidatorDefaultValues((RsaKeyValidator) keyValidator);
        } else if (keyValidator instanceof EccKeyValidator) {
            assertEccKeyValidatorDefaultValues((EccKeyValidator) keyValidator);
        } else if (keyValidator instanceof PublicKeyBlacklistKeyValidator) {
            assertPublicKeyBlacklistKeyValidatorDefaultValues((PublicKeyBlacklistKeyValidator) keyValidator);
        }
    }

    private void assertBaseKeyValidatorDefaultValues(final BaseKeyValidator keyValidator) {
        assertEquals("Latest version expected.", BaseKeyValidator.LATEST_VERSION, keyValidator.getVersion(), 0F);
        assertEquals("Default description expected.", StringUtils.EMPTY, keyValidator.getDescription());
        assertEquals("Default certificate profile ids excepted.", new ArrayList<Integer>(), keyValidator.getCertificateProfileIds());
        assertEquals("Default notBefore expected.", null, keyValidator.getNotBefore());
        assertEquals("Default notBefore condition expected.", KeyValidatorDateConditions.LESS_THAN.getIndex(), keyValidator.getNotBeforeCondition());
        assertEquals("Default notAfter expected.", null, keyValidator.getNotAfter());
        assertEquals("Default notAfter condition expected.", KeyValidatorDateConditions.LESS_THAN.getIndex(), keyValidator.getNotAfterCondition());
        assertEquals("Default failedAction expected.", KeyValidationFailedActions.DO_NOTHING.getIndex(), keyValidator.getFailedAction());
    }

    private void assertEqualsBaseKeyValidator(final BaseKeyValidator left, final BaseKeyValidator right) {
        assertEquals("BaseKeyValidator id must be equal.", left.getKeyValidatorId(), right.getKeyValidatorId());
        assertEquals("BaseKeyValidator name must be equal.", left.getName(), right.getName());
        assertEquals("BaseKeyValidator type must be equal.", left.getType(), right.getType());
        assertEquals("BaseKeyValidator description must be equal.", left.getDescription(), right.getDescription());
        assertEquals("BaseKeyValidator certificate profile id must be equal.", left.getCertificateProfileIds(), right.getCertificateProfileIds());
        assertEquals("BaseKeyValidator notBefore must be equal.", left.getNotBefore(), right.getNotBefore());
        assertEquals("BaseKeyValidator notBeforeCondition must be equal.", left.getNotBeforeCondition(), right.getNotBeforeCondition());
        assertEquals("BaseKeyValidator notAfter must be equal.", left.getNotAfter(), right.getNotAfter());
        assertEquals("BaseKeyValidator notAfterCondition must be equal.", left.getNotAfterCondition(), right.getNotAfterCondition());
        assertEquals("BaseKeyValidator failedAction must be equal.", left.getFailedAction(), right.getFailedAction());
    }

    private void assertRsaKeyValidatorDefaultValues(final RsaKeyValidator keyValidator) {
        assertEquals("RsaKeyValidator must have default bit lengths.", keyValidator.getBitLengths(), new ArrayList<String>());
        assertEquals("RsaKeyValidator must have default public key exponent only allow odd value.", keyValidator.isPublicKeyExponentOnlyAllowOdd(),
                false);
        assertEquals("RsaKeyValidator must have default public key exponent min value.", keyValidator.getPublicKeyExponentMin(), null);
        assertEquals("RsaKeyValidator must have default public key exponent max value.", keyValidator.getPublicKeyExponentMax(), null);
        assertEquals("RsaKeyValidator must have default public key modulus only allow odd value.", keyValidator.isPublicKeyModulusOnlyAllowOdd(),
                false);
        assertEquals("RsaKeyValidator must have default public key modulus do not allow power of prime value.",
                keyValidator.isPublicKeyModulusDontAllowPowerOfPrime(), false);
        assertEquals("RsaKeyValidator must have default public key modulus min value.", keyValidator.getPublicKeyModulusMin(), null);
        assertEquals("RsaKeyValidator must have default public key modulus max value.", keyValidator.getPublicKeyModulusMax(), null);
    }

    private void assertEccKeyValidatorDefaultValues(final EccKeyValidator keyValidator) {
        assertEquals("EccKeyValidator must have default partial validation value.", keyValidator.isUsePartialPublicKeyValidationRoutine(), false);
        assertEquals("EccKeyValidator must have default full validation value.", keyValidator.isUseFullPublicKeyValidationRoutine(), false);
    }

    private void assertPublicKeyBlacklistKeyValidatorDefaultValues(final PublicKeyBlacklistKeyValidator keyValidator) {
        assertEquals("PublicKeyBlacklistKeyValidator must have default key algorithems value.", keyValidator.getKeyAlgorithms(),
                new ArrayList<String>());
        assertEquals("PublicKeyBlacklistKeyValidator must have default key generator sources value.", keyValidator.getKeyGeneratorSources(),
                new ArrayList<Integer>());
    }

    private void assertRsaKeyValidatorCABForumBaseLineRequirements142Values(final RsaKeyValidator keyValidator) {
        assertEquals("RsaKeyValidator with CAB forum settings must have bit lengths.", keyValidator.getBitLengths(),
                RsaKeyValidator.getAvailableBitLengths(RsaKeyValidator.CAB_FORUM_BLR_142_KEY_SIZE_MIN));
        assertEquals("RsaKeyValidator with CAB forum settings must have public key exponent only allow odd value.",
                keyValidator.isPublicKeyExponentOnlyAllowOdd(), RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_EXPONENT_ONLY_ALLOW_ODD);
        assertEquals("RsaKeyValidator with CAB forum settings must have public key exponent min value.", keyValidator.getPublicKeyExponentMin(),
                new BigInteger(RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MIN));
        assertEquals("RsaKeyValidator with CAB forum settings must have public key exponent max value.", keyValidator.getPublicKeyExponentMax(),
                new BigInteger(RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_EXPONENT_MAX));
        assertEquals("RsaKeyValidator with CAB forum settings must have public key modulus only allow odd value.",
                keyValidator.isPublicKeyModulusOnlyAllowOdd(), RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_MODULUS_ONLY_ALLOW_ODD);
        assertEquals("RsaKeyValidator with CAB forum settings must have public key modulus do not allow power of prime value.",
                keyValidator.isPublicKeyModulusDontAllowPowerOfPrime(), RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_MODULUS_DONT_ALLOW_POWER_OF_PRIME);
        assertEquals("RsaKeyValidator with CAB forum settings must have min factor value.", new Integer(keyValidator.getPublicKeyModulusMinFactor()),
                new Integer(RsaKeyValidator.CAB_FORUM_BLR_142_PUBLIC_MODULUS_SMALLEST_FACTOR));
        assertEquals("RsaKeyValidator with CAB forum settings must have public key modulus min value.", keyValidator.getPublicKeyModulusMin(), null);
        assertEquals("RsaKeyValidator with CAB forum settings must have public key modulus max value.", keyValidator.getPublicKeyModulusMax(), null);
    }

    private void assertEccKeyValidatorCABForumBaseLineRequirements142Values(final EccKeyValidator keyValidator) {
        assertEquals("EccKeyValidator with CAB forum settings must have default partial validation value.",
                keyValidator.isUsePartialPublicKeyValidationRoutine(), true);
        assertEquals("EccKeyValidator with CAB forum settings must have default full validation value.",
                keyValidator.isUseFullPublicKeyValidationRoutine(), true);
    }

    private CertificateProfile createTestCertificateProfile(final String name) throws Exception {
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_NO_PROFILE);

        final List<Integer> availableCaIds = new ArrayList<Integer>();
        availableCaIds.add(testCA.getCAId());
        profile.setAvailableCAs(availableCaIds);

        final List<Integer> availableBitLengths = new ArrayList<Integer>();
        availableBitLengths.add(2048);
        profile.setAvailableBitLengths(availableBitLengths);

        final List<String> availableKeyAlgorithms = new ArrayList<String>();
        availableKeyAlgorithms.add("RSA");
        profile.setAvailableKeyAlgorithmsAsList(availableKeyAlgorithms);
        profile.setSignatureAlgorithm("SHA256WithRSA");
        certificateProfileSession.addCertificateProfile(internalAdmin, name, profile);

        final CertificateProfile result = certificateProfileSession.getCertificateProfile(name);
        assertNotNull(result);
        if (log.isDebugEnabled()) {
            log.debug("Test certificate profile " + name + " stored.");
        }
        return result;
    }

    private EndEntityProfile createTestEndEntityProfile(final String name) throws Exception {
        final EndEntityProfile profile = new EndEntityProfile();
        //        profile.addField(EndEntityProfile.CARDNUMBER);
        //        profile.setRequired(EndEntityProfile.CARDNUMBER, 0, true);
        //        profile.setUse(EndEntityProfile.STARTTIME, 0, true);
        //        profile.setUse(EndEntityProfile.ENDTIME, 0, true);
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, String.valueOf(testCA.getCAId()));
        profile.setValue(EndEntityProfile.DEFAULTCA, 0, String.valueOf(testCA.getCAId()));
        final int id = certificateProfileSession.getCertificateProfileId(TEST_CP_NAME);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, String.valueOf(id));
        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, String.valueOf(id));
        endEntityProfileSession.addEndEntityProfile(internalAdmin, name, profile);
        final EndEntityProfile result = endEntityProfileSession.getEndEntityProfile(name);
        assertNotNull(result);
        if (log.isDebugEnabled()) {
            log.debug("Test end entity profile " + name + " stored.");
        }
        return result;
    }

    private EndEntityInformation createTestEndEntity(final String name) throws Exception {
        final int cpId = certificateProfileSession.getCertificateProfileId(TEST_CP_NAME);
        final int eepId = endEntityProfileSession.getEndEntityProfileId(TEST_EEP_NAME);
        final EndEntityInformation user = new EndEntityInformation(name, "CN=" + name, testCA.getCAId(), null, "anjakobs@primekey.se",
                new EndEntityType(EndEntityTypes.ENDUSER), eepId, cpId, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setStatus(EndEntityConstants.STATUS_NEW);
        user.setPassword(TEST_EE_PASSWORD);
        user.setEndEntityProfileId(endEntityProfileSession.getEndEntityProfileId(TEST_EEP_NAME));
        endEntityManagementSessionRemote.addUser(internalAdmin, user, false);
        final Collection<EndEntityInformation> result = endEntityManagementSessionRemote.findAllUsersByCaId(internalAdmin, testCA.getCAId());
        assertNotNull(result);
        Object o = result.toArray()[0];
        assertNotNull(o);
        return (EndEntityInformation) o;
    }

    private void setKeyValidatorsForCa(final CA ca, BaseKeyValidator... keyValidators) throws AuthorizationDeniedException, CADoesntExistsException {
        ca.getCAInfo().getKeyValidators().clear();
        for (BaseKeyValidator keyValidator : keyValidators) {
            ca.getCAInfo().getKeyValidators().add(keyValidatorProxySession.getKeyValidator(keyValidator.getName()).getKeyValidatorId());
        }
        caSession.editCA(internalAdmin, ca.getCAInfo());
        ca.setCAInfo(caSession.getCAInfo(internalAdmin, ca.getCAId()));
    }

    private void removeKeyValidatorsIfExist(String... names) throws Exception {
        for (String name : names) {
            try {
                if (keyValidatorProxySession.getKeyValidator(name) != null) {
                    log.info("Key validator" + name + " exists and will be removed.");
                    keyValidatorProxySession.removeKeyValidator(internalAdmin, name);
                }
            } catch (Exception e) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not remove key validator: " + e.getMessage(), e);
                }
                throw e;
            }
        }
    }

    private void removeCAIfExist(final String name) throws Exception {
        try {
            final CAInfo caInfo = caSession.getCAInfo(internalAdmin, name);
            log.info("CA " + name + " exists and will be removed.");
            caSession.removeCA(internalAdmin, caInfo.getCAId());
        } catch (CADoesntExistsException e) {
            // NOOP
        }
    }

    private void removeCertificateProfileIfExist(final String name) throws Exception {
        if (certificateProfileSession.getCertificateProfile(name) != null) {
            log.info("Certificate profile " + name + " exists and will be removed.");
            certificateProfileSession.removeCertificateProfile(internalAdmin, name);
        }
    }

    private void removeEndEntityProfileIfExist(final String name) throws Exception {
        if (endEntityProfileSession.getEndEntityProfile(name) != null) {
            log.info("End entity profile " + name + " exists and will be removed.");
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, name);
        }
    }

    private void removeUserIfExists(final String name) throws Exception {
        if (endEntityManagementSessionRemote.existsUser(name)) {
            log.info("End entity " + name + " exists and will be removed.");
            endEntityManagementSessionRemote.revokeAndDeleteUser(internalAdmin, name, ReasonFlags.UNUSED);
        }
    }

    public static final KeyPair generateRsaKeyPair(final int size) throws NoSuchProviderException, NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(size); // createFixedRandom()
        return generator.generateKeyPair();
    }

    // Code duplication: see org.cesecore.keys.validation.KeyValidatorTestUtil
    public static final BaseKeyValidator createKeyValidator(final int type, final String name, final String description, final Date notBefore,
            final int notBeforeCondition, final Date notAfter, final int notAfterCondition, final int failedAction,
            final Integer... certificateProfileIds) {
        BaseKeyValidator result;
        if (RsaKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new RsaKeyValidator();
        } else if (EccKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new EccKeyValidator();
        } else if (PublicKeyBlacklistKeyValidator.KEY_VALIDATOR_TYPE == type) {
            result = new PublicKeyBlacklistKeyValidator();
        } else {
            return null;
        }
        result.setName(name);
        if (null != description) {
            result.setDescription(description);
        }
        if (null != notBefore) {
            result.setNotBefore(notBefore);
        }
        if (-1 < notBeforeCondition) {
            result.setNotBeforeCondition(notBeforeCondition);
        }
        if (null != notAfter) {
            result.setNotAfter(notAfter);
        }
        if (-1 < notAfterCondition) {
            result.setNotAfterCondition(notAfterCondition);
        }
        if (-1 < failedAction) {
            result.setFailedAction(failedAction);
        }
        final List<Integer> ids = new ArrayList<Integer>();
        for (Integer id : certificateProfileIds) {
            ids.add(id);
        }
        result.setCertificateProfileIds(ids);
        return result;
    }
}
