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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

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
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.validation.PublicKeyBlacklistKeyValidator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests Key validator session.
 * 
 * @version $Id$
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

    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        
    private KeyValidatorProxySessionRemote keyValidatorProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorProxySessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);

    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);

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
    public void testAddChangeRemoveKeyValidators() throws Exception {
        log.trace(">test01AddChangeRemoveKeyValidators()");
        // Create some test data.
        final Validator rsaKeyValidatorDefault = createKeyValidator(RsaKeyValidator.class, "rsa-test-1-default", null, null, -1,
                null, -1, -1);
        final Validator rsaKeyValidator = createKeyValidator(RsaKeyValidator.class, "rsa-test-2", null, null, -1, null, -1, -1);
        ((RsaKeyValidator) rsaKeyValidator).setCABForumBaseLineRequirements142Settings();
        assertRsaKeyValidatorCABForumBaseLineRequirements142Values((RsaKeyValidator) rsaKeyValidator);

        final Validator eccKeyValidatorDefault = createKeyValidator(EccKeyValidator.class, "ecc-test-1-default", null, null, -1,
                null, -1, -1);
        final Validator eccKeyValidator = createKeyValidator(EccKeyValidator.class, "ecc-test-2", null, null, -1, null, -1, -1);
        ((EccKeyValidator) eccKeyValidator).setCABForumBaseLineRequirements142();
        assertEccKeyValidatorCABForumBaseLineRequirements142Values((EccKeyValidator) eccKeyValidator);

      
        int[] allIdentifiers = new int[] {};
        try {
            // A: Add different new key validators.
            int rsaDefaultId = addKeyValidator(rsaKeyValidatorDefault);
            int rsaId = addKeyValidator(rsaKeyValidator);
            int eccDefaultId = addKeyValidator(eccKeyValidatorDefault);
            int eccId = addKeyValidator(eccKeyValidator);
            allIdentifiers = new int[] { rsaDefaultId, rsaId, eccDefaultId, eccId };
            // A-1: Check add with defaults.
            // RSA key validator
            Validator keyValidator = keyValidatorProxySession.getKeyValidator(rsaDefaultId);
            assertKeyValidatorDefaultValues(keyValidator);
            // ECC key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(eccDefaultId);
            assertKeyValidatorDefaultValues(keyValidator);

            // A-2: Check change and load again with custom values.
            // RSA key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(rsaDefaultId);
            ((RsaKeyValidator) keyValidator).setCABForumBaseLineRequirements142Settings();
            keyValidatorProxySession.changeKeyValidator(internalAdmin, keyValidator);
            Validator testKeyValidator = keyValidatorProxySession.getKeyValidator(keyValidator.getProfileId());
            assertEqualsBaseKeyValidator(keyValidator, testKeyValidator);
            assertRsaKeyValidatorCABForumBaseLineRequirements142Values((RsaKeyValidator) testKeyValidator);
            // ECC key validator
            keyValidator = keyValidatorProxySession.getKeyValidator(eccDefaultId);
            ((EccKeyValidator) keyValidator).setCABForumBaseLineRequirements142();
            keyValidatorProxySession.changeKeyValidator(internalAdmin, keyValidator);
            testKeyValidator = keyValidatorProxySession.getKeyValidator(keyValidator.getProfileId());
            assertEqualsBaseKeyValidator(keyValidator, testKeyValidator);
            assertEccKeyValidatorCABForumBaseLineRequirements142Values((EccKeyValidator) testKeyValidator);

            // A-3: Remove key validators.
            try {
                removeKeyValidatorsIfExist(allIdentifiers);
                assertKeyValidatorsNotExist(allIdentifiers);
            } catch (CouldNotRemoveKeyValidatorException e) {
                fail("Key validators have no references on other entities, so no exceptions should be thrown.");
            }
            assertKeyValidatorsNotExist(allIdentifiers);

            // Check Referential integrity: 
            // Add to test CA and try to remove it -> CouldNot RemoveKeyValidatorException expected.
            String name = "rsa-test-1-referential-integrity";
            keyValidator = createKeyValidator(RsaKeyValidator.class, name, null, null, -1, null, -1, -1);
            int validatorId = addKeyValidator(keyValidator);
            setKeyValidatorsForCa(testCA, validatorId);
            try {
                keyValidatorProxySession.removeKeyValidator(internalAdmin, validatorId);
                assertKeyValidatorsExist(validatorId);
                fail("Key validator with name " + name + " must not be removed because referential integrity.");
            } catch (CouldNotRemoveKeyValidatorException e) {
                setKeyValidatorsForCa(testCA);
                keyValidatorProxySession.removeKeyValidator(internalAdmin, validatorId);
                assertKeyValidatorsNotExist(validatorId);
            }
        } finally {
            CaTestUtils.removeCa(internalAdmin, testCA.getCAInfo());
            removeKeyValidatorsIfExist(allIdentifiers);
        }
        log.trace("<test01AddChangeRemoveKeyValidators()");
    }

    @Test
    public void testValidateRsaPublicKey() throws Exception {
        log.trace(">test02ValidateRsaPublicKey()");

        // A-1: Check validation of non RSA key, use ECC key instead -> KeyValidationIllegalKeyAlgorithmException expected.
        KeyPair keyPair = KeyTools.genKeys("prime192v1", AlgorithmConstants.KEYALGORITHM_ECDSA); // generateEcCurve("prime192v1");
        PublicKey publicKey = keyPair.getPublic();
        Validator keyValidator = createKeyValidator(RsaKeyValidator.class, "rsa-test-1-default", null, null, -1, null, -1,
                KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex(), certificateProfileSession.getCertificateProfileId(TEST_CP_NAME));
        int validatorId = addKeyValidator(keyValidator);
        keyValidator.setProfileId(validatorId);
        try {
            setKeyValidatorsForCa(testCA, validatorId);
            try {
                keyValidatorProxySession.validatePublicKey(internalAdmin, testCA, testUser, testCertificateProfile, new Date(new Date().getTime() - 1000 * 86400),
                        new Date(new Date().getTime() + 1000 * 86400), publicKey);
                fail("RSA key validator successfully validated an ECC key.");
            } catch (Exception e) {
                assertTrue("KeyValidationException expected when a RSA key validator tries to validate an ECC key: " + keyValidator.getProfileName(),
                        e instanceof KeyValidationIllegalKeyAlgorithmException);
            }

            // B-1: Check valid RSA key -> issuance MUST be OK.
            keyPair = generateRsaKeyPair(2048); // KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
            publicKey = keyPair.getPublic();
            System.out.println("Keytype: "+publicKey.getAlgorithm());
            try {
                final boolean result = keyValidatorProxySession.validatePublicKey(internalAdmin, testCA, testUser, testCertificateProfile,
                        new Date(new Date().getTime() - 1000 * 86400), new Date(new Date().getTime() + 1000 * 86400), publicKey);
                assertTrue("2048 bit RSA key should validate with default settings.", result);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
                e.printStackTrace();
                fail("2048 bit RSA key validation failed with exception for default RSA key validator: " + e.getMessage());
            }

            // B-2: Check invalid RSA key with small key size and failed action 'Abort certificate issuance' -> issuance MUST be aborted.
            keyPair = generateRsaKeyPair(512); // KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            publicKey = keyPair.getPublic();
            try {
                final boolean result = keyValidatorProxySession.validatePublicKey(internalAdmin, testCA, testUser, testCertificateProfile,
                        new Date(new Date().getTime() - 1000 * 86400), new Date(new Date().getTime() + 1000 * 86400), publicKey);
                fail("With action 'Abort certificate issuance an exception should be thrown: " + result);
            } catch (Exception e) {
                // Exception expected here
                log.info(e.getMessage(), e);
            }

            // B-3: Check invalid RSA key with failed action NOT 'Abort certificate issuance' -> issuance SHOULD NOT be aborted.
            keyPair = generateRsaKeyPair(512); // KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
            publicKey = keyPair.getPublic();
            keyValidator.setFailedAction(KeyValidationFailedActions.LOG_WARN.getIndex());
            keyValidatorProxySession.changeKeyValidator(internalAdmin, keyValidator);
            try {
                final boolean result = keyValidatorProxySession.validatePublicKey(internalAdmin, testCA, testUser, testCertificateProfile,
                        new Date(new Date().getTime() - 1000 * 86400), new Date(new Date().getTime() + 1000 * 86400), publicKey);
                assertFalse("512 bit RSA key should not validate with default settings.", result);
            } catch (Exception e) {
                log.error(e.getMessage(), e);
                fail("512 bit RSA key validation failed with exception for default RSA key validator: " + e.getMessage());
            }

            // Test server generated keys.
            //        KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);

        } finally {
            CaTestUtils.removeCa(internalAdmin, testCA.getCAInfo());
            keyValidatorProxySession.removeKeyValidator(internalAdmin, validatorId);
        }
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
    //        assertTrue("Public key validation without any key validator defined should validate to true.", result);
    //
    //        log.trace("<test03ValidatePublicKey()");
    //    }

    /**
     * Test of the cache of validators. This test depends on cache time of 1 second being used.
     */
    @Test
    public void testKeyValidatorCache() throws Exception {
        // First make sure we have the right cache time
        final String oldcachetime = cesecoreConfigurationProxySession.getConfigurationValue("validator.cachetime");
        cesecoreConfigurationProxySession.setConfigurationValue("validator.cachetime", "1000");
        final String name = "testKeyValidatorCache";
        final Validator rsaKeyValidator = createKeyValidator(RsaKeyValidator.class, name, null, null, -1, null, -1, -1);
        rsaKeyValidator.setDescription("foobar");
        int id = 0; // id of the Validator we will add
        try {
            // See if we have to remove the old validator first
            final Map<String, Integer> nameMap = keyValidatorProxySession.getKeyValidatorNameToIdMap();
            if (nameMap.containsKey(name)) {
                final int idtoremove = nameMap.get(name);
                keyValidatorProxySession.removeKeyValidator(internalAdmin, idtoremove);                
            }
            // Add a Validator
            id = keyValidatorProxySession.addKeyValidator(internalAdmin, rsaKeyValidator);
            // Make sure Validator has the right value from the beginning
            Validator val = keyValidatorProxySession.getKeyValidator(id);
            assertEquals("Description is not what we set", "foobar", val.getDescription());
            // Change publisher
            val.setDescription("bar");
            keyValidatorProxySession.changeKeyValidator(internalAdmin, val);
            // Read Validator again, cache should have been updated directly
            val = keyValidatorProxySession.getKeyValidator(val.getProfileId());
            assertEquals("bar", val.getDescription());
            // Flush caches to reset cache timeout
            keyValidatorProxySession.flushKeyValidatorCache();
            /// Read Validator to ensure it is in cache
            val = keyValidatorProxySession.getKeyValidator(val.getProfileId());
            assertEquals("bar", val.getDescription());
            // Change validator not flushing cache, old value should remain when reading
            val.setDescription("newvalue");
            //keyValidatorProxySession.changeKeyValidator(internalAdmin, val);
            keyValidatorProxySession.internalChangeValidatorNoFlushCache(val);
            val = keyValidatorProxySession.getKeyValidator(val.getProfileId());
            assertEquals("bar", val.getDescription()); // old value
            // Wait 2 seconds and try again, now the cache should have been updated
            Thread.sleep(2000);
            val = keyValidatorProxySession.getKeyValidator(val.getProfileId());
            assertEquals("newvalue", val.getDescription()); // new value
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue("validator.cachetime", oldcachetime);
            keyValidatorProxySession.removeKeyValidator(internalAdmin, id);                
        }
    }

    private void assertKeyValidatorsExist(final int... identifiers) {
        for (int identifier : identifiers) {
            assertNotNull("Added key validator (id=" + identifier + ") must be retrieved by datastore. ", keyValidatorProxySession.getKeyValidator(identifier));
        }
    }

    private void assertKeyValidatorsNotExist(final int... identifiers) {
        for (int identifier : identifiers) {
            assertNull("Removed key validator must not be retrieved by datastore. ", keyValidatorProxySession.getKeyValidator(identifier));
        }
    }

    private int addKeyValidator(Validator keyValidator) throws AuthorizationDeniedException, KeyValidatorExistsException {
        int id = keyValidatorProxySession.addKeyValidator(internalAdmin, keyValidator);
        assertKeyValidatorsExist(id);
        return id;
    }

    private void assertKeyValidatorDefaultValues(final Validator keyValidator) {
        assertBaseKeyValidatorDefaultValues(keyValidator);
        if (keyValidator instanceof RsaKeyValidator) {
            assertRsaKeyValidatorDefaultValues((RsaKeyValidator) keyValidator);
        } else if (keyValidator instanceof EccKeyValidator) {
            assertEccKeyValidatorDefaultValues((EccKeyValidator) keyValidator);
        } else if (keyValidator instanceof PublicKeyBlacklistKeyValidator) {
            assertPublicKeyBlacklistKeyValidatorDefaultValues((PublicKeyBlacklistKeyValidator) keyValidator);
        }
    }

    private void assertBaseKeyValidatorDefaultValues(final Validator keyValidator) {
        assertEquals("Latest version expected.", KeyValidatorBase.LATEST_VERSION, keyValidator.getLatestVersion(), 1f);
        assertEquals("Default description expected.", StringUtils.EMPTY, keyValidator.getDescription());
        assertEquals("Default certificate profile ids excepted.", new ArrayList<Integer>(), keyValidator.getCertificateProfileIds());
        assertEquals("Default all certificate profile ids excepted.", true, keyValidator.isAllCertificateProfileIds());
        assertEquals("Default notBefore expected.", null, keyValidator.getNotBefore());
        assertEquals("Default notBefore condition expected.", KeyValidatorDateConditions.LESS_THAN.getIndex(), keyValidator.getNotBeforeCondition());
        assertEquals("Default notAfter expected.", null, keyValidator.getNotAfter());
        assertEquals("Default notAfter condition expected.", KeyValidatorDateConditions.LESS_THAN.getIndex(), keyValidator.getNotAfterCondition());
        assertEquals("Default failedAction expected.", KeyValidationFailedActions.ABORT_CERTIFICATE_ISSUANCE.getIndex(), keyValidator.getFailedAction());
    }

    private void assertEqualsBaseKeyValidator(final Validator left, final Validator right) {
        assertEquals("BaseKeyValidator id must be equal.", left.getProfileId(), right.getProfileId());
        assertEquals("BaseKeyValidator name must be equal.", left.getProfileName(), right.getProfileName());
        assertEquals("BaseKeyValidator type must be equal.", left.getValidatorTypeIdentifier(), right.getValidatorTypeIdentifier());
        assertEquals("BaseKeyValidator description must be equal.", left.getDescription(), right.getDescription());
        assertEquals("BaseKeyValidator all certificate profile ids must be equal.", left.isAllCertificateProfileIds(), right.isAllCertificateProfileIds());
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

    private void setKeyValidatorsForCa(final CA ca, int... validatorIds) throws AuthorizationDeniedException, CADoesntExistsException {
        ca.getCAInfo().getValidators().clear();
        for (int validatorId : validatorIds) {
            ca.getCAInfo().getValidators().add(validatorId);
        }
        caSession.editCA(internalAdmin, ca.getCAInfo());
        ca.setCAInfo(caSession.getCAInfo(internalAdmin, ca.getCAId()));
    }

    private void removeKeyValidatorsIfExist(int... identifiers) throws Exception {
        for (int identifier : identifiers) {
            try {
                if (keyValidatorProxySession.getKeyValidator(identifier) != null) {
                    log.info("Key validator with ID" + identifier + " exists and will be removed.");
                    keyValidatorProxySession.removeKeyValidator(internalAdmin, identifier);
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
            endEntityManagementSessionRemote.revokeAndDeleteUser(internalAdmin, name, ReasonFlags.unused);
        }
        internalCertificateStoreSession.removeCertificatesByUsername(name);
    }

    public static final KeyPair generateRsaKeyPair(final int size) throws NoSuchProviderException, NoSuchAlgorithmException {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); // Use default provider
        // Using BC provider, i.e. creating a BC public key object causes test failure
        // in JDK7+JBOSS 7.1.1 combo
        //final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(size); // createFixedRandom()
        return generator.generateKeyPair();
    }

    // Code duplication: see org.cesecore.keys.validation.KeyValidatorTestUtil
    public static final Validator createKeyValidator(final Class<? extends Validator> type, final String name, final String description, final Date notBefore,
            final int notBeforeCondition, final Date notAfter, final int notAfterCondition, final int failedAction,
            final Integer... certificateProfileIds) throws InstantiationException, IllegalAccessException {
        Validator result = type.newInstance();
        result.setProfileName(name);
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
    
    @Test
    public void testImportFromZip() throws Exception {
        final String keyValidatorWithIdName = "keyValidatorWithId";
        final Validator keyValidatorWithId = createKeyValidator(RsaKeyValidator.class, keyValidatorWithIdName, null, null, -1, null, -1, -1);
        int keyValidatorId = 4711;
        keyValidatorWithId.setProfileId(keyValidatorId);
        final String keyValidatorWithoutIdName = "keyValidatorWithoutId";
        final Validator keyValidatorWithoutId = createKeyValidator(RsaKeyValidator.class, keyValidatorWithoutIdName, null, null, -1, null, -1, -1);
        //Export the validators to a zip
        ByteArrayOutputStream zbaos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(zbaos);
        String keyValidatorWithIdNameEncoded = URLEncoder.encode(keyValidatorWithId.getProfileName(), "UTF-8");
        String keyValidatorWithoutIdNameEncoded = URLEncoder.encode(keyValidatorWithoutId.getProfileName(), "UTF-8");
        byte[] keyValidatorWithIdNameEncodedBytes = getProfileBytes(keyValidatorWithId);
        byte[] keyValidatorWithoutIdNameEncodedBytes = getProfileBytes(keyValidatorWithoutId);
        String keyValidatorWithIdNameFilename = "keyvalidator_" + keyValidatorWithIdNameEncoded + "-" + keyValidatorId + ".xml";
        String keyValidatorWithoutIdNameFilename = "keyvalidator_" + keyValidatorWithoutIdNameEncoded + "-" + -1 + ".xml";
        ZipEntry ze = new ZipEntry(keyValidatorWithIdNameFilename);
        zos.putNextEntry(ze);
        zos.write(keyValidatorWithIdNameEncodedBytes);
        zos.closeEntry();
        ze = new ZipEntry(keyValidatorWithoutIdNameFilename);
        zos.putNextEntry(ze);
        zos.write(keyValidatorWithoutIdNameEncodedBytes);
        zos.closeEntry();
        zos.close();
        final byte[] zipfile = zbaos.toByteArray();
        zbaos.close();
        ValidatorImportResult result = keyValidatorProxySession.importKeyValidatorsFromZip(internalAdmin, zipfile);
        try {
            List<Validator> validators = result.getImportedValidators();
            assertEquals("Both validators weren't imported.", 2, validators.size());
        } finally {
            for (Validator validator : result.getImportedValidators()) {
                removeKeyValidatorsIfExist(validator.getProfileId());
            }
        }
    }
    
    private byte[] getProfileBytes(UpgradeableDataHashMap profile) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(profile.saveData());
        encoder.close();
        byte[] ba = baos.toByteArray();
        baos.close();
        return ba;
    }
    
    private byte[] getProfileBytes(Validator profile) throws IOException {
        return getProfileBytes(profile.getUpgradableHashmap());
    }
}
