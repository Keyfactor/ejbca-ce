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
 * @version $Id$
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
 * Tests RSA key validator functions.
 * 
 * @version $Id$
 */
public class RsaKeyValidatorTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(RsaKeyValidatorTest.class);

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
    public void test01HasSmallerFactorThan() throws Exception {
        log.trace(">test01HasSmallerFactorThan()");

        // Test both zero -> false
        BigInteger modulus = new BigInteger("0");
        Assert.assertFalse("Modulus 0 and factor 0 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 0));

        // Factor is smaller than modulus -> false;
        Assert.assertFalse("Modulus 0 and factor 1 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 1));

        // Test both 1 -> false;
        modulus = new BigInteger("1");
        Assert.assertFalse("Modulus 1 and factor 1 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 1));

        // Test both 2 -> false;
        modulus = new BigInteger("2");
        Assert.assertFalse("Modulus 2 and factor 2 must evaluate to false.", RsaKeyValidator.hasSmallerFactorThan(modulus, 2));

        // All even numbers have the smallest factor 2 -> false;
        modulus = new BigInteger("12345678902");
        Assert.assertFalse("Even modulus must evaluate to smallest factor 2.", RsaKeyValidator.hasSmallerFactorThan(modulus, 2));
        Assert.assertTrue("Even modulus must evaluate to smallest factor 2.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));

        // Prime numbers smallest factor except 1 is itself.
        modulus = new BigInteger("3");
        Assert.assertTrue("A primes smallest factor except 1 is itself.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));
        modulus = new BigInteger("123");
        Assert.assertTrue("A primes smallest factor except 1 is itself.", RsaKeyValidator.hasSmallerFactorThan(modulus, 123));
        modulus = new BigInteger("9");
        Assert.assertTrue("The smallest factor of 9 is 3.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));
        modulus = new BigInteger("27");
        Assert.assertTrue("The smallest factor of 27 is 3.", RsaKeyValidator.hasSmallerFactorThan(modulus, 3));

        // Test large modulus.
        long time = System.currentTimeMillis();
        modulus = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390782");
        Assert.assertTrue("Test 2048 bits even modulus", RsaKeyValidator.hasSmallerFactorThan(modulus, 752));
        log.trace(">test01HasSmallerFactorThan() ms spent for 2048 bit even modulus: " + (System.currentTimeMillis() - time));

        BigInteger modulus2048 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        BigInteger modulus4096 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        BigInteger modulus8192 = new BigInteger(
                "135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781135253271074378184290126435546666091495057097246829408541196270645232645477924688225635651598675866808820785572943817237337557196378645497560351383628324706536080486180455448996646985667891738346505771576771134762012536044972691177382786401341057394042017796805414677173199794244010442024923795849646025390781");
        // Can be a time consuming task!
        int factor = 1522342;
        profileHasSmallerFactor(factor, new BigInteger[] { modulus2048, modulus4096, modulus8192 });

        log.trace("<test01HasSmallerFactorThan()");
    }

    @Test
    public void test03RsaParameterValidations() throws Exception {
        log.trace(">test03RsaParameterValidations()");

        final KeyFactory keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);

        // A-1: Test RSA key validation OK with default settings except key size.
        BigInteger modulus = BigInteger.valueOf(15);
        BigInteger exponent = BigInteger.valueOf(3);
        PublicKey publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-1", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        // Set custom bit length.
        List<String> bitLengths = new ArrayList<String>();
        bitLengths.add(Integer.toString(modulus.bitLength()));
        keyValidator.setBitLengths(bitLengths);
        List<String> messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertTrue("Key validation should have been successful.", messages.size() == 0);

        // A-2: Test RSA key validation failed RSA parameter bounds with even parameters.
        modulus = BigInteger.valueOf(16);
        exponent = BigInteger.valueOf(4);
        publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        keyValidator.setPublicKeyExponentMin(exponent.add(BigInteger.ONE));
        keyValidator.setPublicKeyExponentMax(exponent.subtract(BigInteger.ONE));
        keyValidator.setPublicKeyExponentOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMin(modulus.add(BigInteger.ONE));
        keyValidator.setPublicKeyModulusMax(modulus.subtract(BigInteger.ONE));
        keyValidator.setPublicKeyModulusOnlyAllowOdd(true);
        //        keyValidator.setPublicKeyModulusMinFactor(2);
        bitLengths = new ArrayList<String>();
        bitLengths.add(Integer.toString(modulus.bitLength()));
        keyValidator.setBitLengths(bitLengths);
        messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertTrue("Key valildation should have failed because of even RSA parameter and outside parameter bounds.",
                messages.size() == 6);
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is odd.", messages.get(0));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is smaller than 5", messages.get(1));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is greater than 3", messages.get(2));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is odd.", messages.get(3));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is smaller than 17", messages.get(4));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is greater than 15", messages.get(5));

        // A-3: Test RSA key validation failed because of modulus factor restriction.
        modulus = BigInteger.valueOf(25);
        exponent = BigInteger.valueOf(3);
        publicKey = keyFactory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
        keyValidator.setPublicKeyExponentMin(exponent);
        keyValidator.setPublicKeyExponentMax(exponent);
        keyValidator.setPublicKeyExponentOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMin(modulus);
        keyValidator.setPublicKeyModulusMax(modulus);
        keyValidator.setPublicKeyModulusOnlyAllowOdd(true);
        keyValidator.setPublicKeyModulusMinFactor(6); // smallest factor = 5
        messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertTrue("Key valildation should have failed because of smallest factor restriction for modulus.",
                messages.size() == 1);
        Assert.assertEquals("smallest factor failure message isn't right",
                "Invalid: RSA public key modulus smallest factor is less than 6", messages.get(0));

        // A-4: Test RSA key validation failed because of modulus power of prime restriction.
        keyValidator.setPublicKeyModulusMinFactor(5); // smallest factor = 5
        keyValidator.setPublicKeyModulusDontAllowPowerOfPrime(true);
        messages = keyValidator.validate(publicKey, null);
        log.trace("Key validation error messages: " + messages);
        Assert.assertTrue("Key valildation should have failed because of power of prime restriction for modulus.",
                messages.size() == 1);
        Assert.assertEquals("Power of prime failure message isn't right.",
                "Invalid: RSA public key modulus is not allowed to be the power of a prime.", messages.get(0));

        log.trace("<test03RsaParameterValidations()");
    }

    private void profileHasSmallerFactor(final int factor, final BigInteger... modulus) {
        log.trace(">profileHasSmallerFactor()");

        final long time = System.currentTimeMillis();
        int size;
        for (BigInteger m : modulus) {
            size = m.bitLength();
            Assert.assertFalse("Test " + size + " bits modulus", RsaKeyValidator.hasSmallerFactorThan(m, factor));
            if (log.isTraceEnabled()) {
                log.trace(">ms spent for " + size + " bit odd modulus with factor " + factor + ": " + (System.currentTimeMillis() - time));
            }
        }

        log.trace("<profileHasSmallerFactor()");
    }
}
