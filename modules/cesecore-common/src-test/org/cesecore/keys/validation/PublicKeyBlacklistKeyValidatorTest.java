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
 * Test class fot RSA key validator functional methods, see {@link RsaKeyValidator}.
 * 
 * @version $Id: RsaKeyValidatorTest.java 25263 2017-03-01 12:12:00Z anjakobs $
 */
package org.cesecore.keys.validation;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests public key blacklist key validator functions.
 * 
 * @version $Id: PublicKeyBlacklistKeyValidatorTest.java 25500 2017-04-01 11:28:08Z anjakobs $
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
        PublicKeyBlacklistKeyValidator keyValidator = (PublicKeyBlacklistKeyValidator) KeyValidatorTestUtil.createKeyValidator(
                PublicKeyBlacklistKeyValidator.KEY_VALIDATOR_TYPE, "publickey-blacklist-validation-test-1", "Description", null, -1, null, -1, -1,
                new Integer[] {});
        //        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        keyValidator.setBlacklistProducer(new PublicKeyBlacklistProducer() {
            @Override
            public PublicKeyBlacklist findByFingerprint(String fingerprint) {
                return null;
            }
        });
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
        keyValidator.setBlacklistProducer(new PublicKeyBlacklistProducer() {
            @Override
            public PublicKeyBlacklist findByFingerprint(String fingerprint) {
                final PublicKeyBlacklist result = new PublicKeyBlacklist();
                result.setFingerprint(fingerprint);
                return result;
            }
        });
        result = keyValidator.validate(publicKey);
        log.trace("Key validation error messages: " + keyValidator.getMessages());
        Assert.assertTrue("Key valildation should have failed because of public key fingerprint match.",
                !result && keyValidator.getMessages().size() == 1);

        // B-1: Test public key blacklist validation OK with match but other algorithm.
        keyValidator.getMessages().clear();
        algorithms = new ArrayList<String>();
        algorithms.add("DSA");
        keyValidator.setKeyAlgorithms(algorithms);
        keyValidator.setBlacklistProducer(new PublicKeyBlacklistProducer() {
            @Override
            public PublicKeyBlacklist findByFingerprint(String fingerprint) {
                final PublicKeyBlacklist result = new PublicKeyBlacklist();
                result.setFingerprint(fingerprint);
                result.setKeyspec("RSA2048");
                return result;
            }
        });
        result = keyValidator.validate(publicKey);
        log.trace("Key validation error messages: " + keyValidator.getMessages());
        Assert.assertTrue("Key valildation should have been successful because of public key fingerprint match but other algorithm.",
                result && keyValidator.getMessages().size() == 0);
        
        log.trace("<test01MatchBlacklistedPublicKey()");
    }
}
