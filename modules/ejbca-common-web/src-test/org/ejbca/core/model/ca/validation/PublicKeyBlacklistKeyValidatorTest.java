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

/**
 * Test class fot public key blacklist key validator functional methods.
 * 
 * @version $Id$
 */
package org.ejbca.core.model.ca.validation;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.validation.BaseKeyValidator;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ca.validation.PublicKeyBlacklistData;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests public key blacklist key validator functions.
 * 
 * @version $Id$
 */
public class PublicKeyBlacklistKeyValidatorTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistKeyValidatorTest.class);

    @BeforeClass
    public static void setClassUp() throws Exception {
        log.trace("setClassUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("setClassUp()");
    }

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        // NOOP
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        // NOOP
        log.trace("<tearDown()");
    }

    @Test
    public void test01MatchBlacklistedPublicKey() throws Exception {
        log.trace(">test01MatchBlacklistedPublicKey()");

        final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);

        // A: Test public key blacklist validation OK with empty blacklist.
        BigInteger modulus = BigInteger.valueOf(6553765537L);
        BigInteger exponent = BigInteger.valueOf(65537);
        PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        PublicKeyBlacklistKeyValidator keyValidator = (PublicKeyBlacklistKeyValidator) createKeyValidator(
                PublicKeyBlacklistKeyValidator.KEY_VALIDATOR_TYPE, "publickey-blacklist-validation-test-1", "Description", null, -1, null, -1, -1,
                new Integer[] {});
        keyValidator.setUseOnlyCache(true); // don't try to make EJB lookup for the "real" blacklist
        //        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        boolean result = keyValidator.validate(publicKey);
        log.trace("Key validation error messages: " + keyValidator.getMessages());
        Assert.assertTrue("Key valildation should have been successful.", result && keyValidator.getMessages().size() == 0);

        // B: Test public key blacklist validation NOK with match.
        keyValidator.getMessages().clear();
        List<String> keyGeneratorSources = new ArrayList<String>();
        keyGeneratorSources.add("-1");
        List<String> algorithms = new ArrayList<String>();
        algorithms.add("-1");
        keyValidator.setKeyGeneratorSources(keyGeneratorSources);
        keyValidator.setKeyAlgorithms(algorithms);
        {
            // Manual update of cache entry
            final String fingerprint = CertTools.createPublicKeyFingerprint(publicKey, PublicKeyBlacklistEntry.DIGEST_ALGORITHM);
            final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
            entry.setFingerprint(fingerprint);
            PublicKeyBlacklistData data = new PublicKeyBlacklistData(entry);
            PublicKeyBlacklistEntryCache.INSTANCE.updateWith(123, data.getProtectString(0).hashCode(), fingerprint, entry);
        }
        result = keyValidator.validate(publicKey);
        log.trace("Key validation error messages: " + keyValidator.getMessages());
        Assert.assertTrue("Key valildation should have failed because of public key fingerprint match.",
                !result && keyValidator.getMessages().size() == 1);

        // B-1: Test public key blacklist validation OK with match but other algorithm.
        keyValidator.getMessages().clear();
        algorithms = new ArrayList<String>();
        algorithms.add("DSA");
        keyValidator.setKeyAlgorithms(algorithms);
        result = keyValidator.validate(publicKey);
        log.trace("Key validation error messages: " + keyValidator.getMessages());
        Assert.assertTrue("Key valildation should have been successful because of public key fingerprint match but other algorithm.",
                result && keyValidator.getMessages().size() == 0);
        
        log.trace("<test01MatchBlacklistedPublicKey()");
    }
    
    /**
     * Factory method to create key validators.
     * 
     * @param type the key validator type (see {@link BaseKeyValidator#KEY_VALIDATOR_TYPE}
     * @param name the logical name
     * @param description the description text
     * @param notBefore the certificates validity not before
     * @param notBeforeCondition the certificates validity not before condition
     * @param notAfter the certificates validity not after
     * @param notAfterCondition the certificates validity not after condition
     * @param failedAction the failed action to be performed.
     * @param certificateProfileIds list of IDs of certificate profile to be applied to. 
     * @return the concrete key validator instance.
     */
    private BaseKeyValidator createKeyValidator(final int type, final String name, final String description, final Date notBefore,
            final int notBeforeCondition, final Date notAfter, final int notAfterCondition, final int failedAction,
            final Integer... certificateProfileIds) {
        BaseKeyValidator result;
        if (PublicKeyBlacklistKeyValidator.KEY_VALIDATOR_TYPE == type) {
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
