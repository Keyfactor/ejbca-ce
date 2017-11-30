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

import static org.junit.Assert.assertEquals;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
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

    /**
     * Testing that no fields for RSA Key Validator configuration can be set to a negative value
     * @throws Exception Exception
     */
    @Test
    public void testNoNegativeNumbers() throws Exception {
        log.trace(">testNoNegativeNumbers()");
        RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-input_test", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        String numStringPos = "2";
        String numStringNeg = "-4";
        BigInteger exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyExponentMin(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyExponentMin(exponent);
        // Test that a negative number can not be set for setPublicKeyExponentMin
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyExponentMinAsString(), numStringPos  );
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyExponentMin(), new BigInteger(numStringPos) );
        // Test that a negative number can not be set for setPublicKeyExponentMax
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyExponentMax(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyExponentMax(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyExponentMaxAsString(), numStringPos  );
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyExponentMax(), new BigInteger(numStringPos)  );
        // Test that a negative number can not be set for setPublicKeyModulusMin
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyModulusMin(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyModulusMin(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyModulusMinAsString(), numStringPos  );
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyModulusMin(),  new BigInteger(numStringPos));
        // Test that a negative number can not be set for setPublicKeyModulusMax
        exponent = new BigInteger(numStringPos);
        keyValidator.setPublicKeyModulusMax(exponent);
        exponent = new BigInteger(numStringNeg);
        keyValidator.setPublicKeyModulusMax(exponent);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyModulusMaxAsString(), numStringPos  );
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyModulusMax(), new BigInteger(numStringPos) );
        // Test that a negative number can not be set for setPublicKeyModulusMinFactor
        keyValidator.setPublicKeyModulusMinFactor(2);
        keyValidator.setPublicKeyModulusMinFactor(-4);
        Assert.assertEquals("Test should not fail, validator field can not be set to a negative value ", 
                keyValidator.getPublicKeyModulusMinFactor(), new Integer("2"));
        log.trace("<testNoNegativeNumbers()");
   }
    
    /**
     * Tests that it is not possible to set a smaller maximum exponent than currently set minimum exponent and vice versa. 
     * @throws Exception Exception
     */
    @Test
    public void testPublicKeyExponentMinSmallerThanMax() throws Exception {
        log.trace(">testPublicKeyExponentMinSmallerThanMax()");
        
        RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-set-min-smaller-max-test", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
        
        // Test that min and max can be changed from null.
        keyValidator.setPublicKeyExponentMinAsString("2"); 
        keyValidator.setPublicKeyExponentMaxAsString("3"); 
        Assert.assertEquals("It should be possible to set minimum exponent to 2 if maximum is null",
                keyValidator.getPublicKeyExponentMinAsString(),"2");
        Assert.assertEquals("It should be possible to set maximum exponent to 3 if miniimum is 2",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");
        // Test not possible to set smaller max than min.
        keyValidator.setPublicKeyExponentMaxAsString("1"); 
        Assert.assertEquals("It should not be possible to set maximum exponent to 1 if minimum is 2",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");
        // Test not possible to set larger min than max.
        keyValidator.setPublicKeyExponentMinAsString("4");
        Assert.assertEquals("It should not be possible to set minimum exponent to 4 if maximum is 3",
                keyValidator.getPublicKeyExponentMinAsString(),"2");
        // Test possible to set same min as max.
        keyValidator.setPublicKeyExponentMinAsString("3"); 
        keyValidator.setPublicKeyExponentMaxAsString("5"); 
        Assert.assertEquals("It should be possible to set minimum exponent to 3 if maximum is 3",
                keyValidator.getPublicKeyExponentMinAsString(),"3");
        Assert.assertEquals("It should be possible to set maximum exponent to 5 if minimum is 3",
                keyValidator.getPublicKeyExponentMaxAsString(),"5");
        // Test possible to set same max as min.
        keyValidator.setPublicKeyExponentMaxAsString("3"); 
        Assert.assertEquals("It should be possible to set maximum exponent to 3 if minimum is 3",
                keyValidator.getPublicKeyExponentMaxAsString(),"3");
        
        log.trace("<testPublicKeyExponentMinSmallerThanMax()");
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
        //        keyValidator.setPublicKeyExponentMax(exponent.subtract(BigInteger.ONE));
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
                messages.size() == 5);
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is odd.", messages.get(0));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is smaller than 5", messages.get(1));
        //        Assert.assertEquals("RSA parameters bounds failure message isn't right",
        //                "Invalid: RSA public key exponent is greater than 3", messages.get(2));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is odd.", messages.get(2));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is smaller than 17", messages.get(3));
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key modulus is greater than 15", messages.get(4));
        // Need to set min to null before lowering max 
        keyValidator.setPublicKeyExponentMin(null);
        keyValidator.setPublicKeyExponentMax(exponent.subtract(BigInteger.ONE));
        keyValidator.validate(publicKey, null);
        Assert.assertEquals("RSA parameters bounds failure message isn't right",
                "Invalid: RSA public key exponent is greater than 3", keyValidator.validate(publicKey, null).get(1));
        
        
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

    /** Tests public key validation for the ROCA vulnerable key generation. CVE-2017-15361
     */
    @Test
    public void testRocaWeakKeys() throws CertificateParsingException, InstantiationException, IllegalAccessException, ValidatorNotApplicableException, ValidationException {
        log.trace(">testRocaWeakKeys()");
        X509Certificate noroca = CertTools.getCertfromByteArray(noRocaCert, X509Certificate.class);
        X509Certificate roca = CertTools.getCertfromByteArray(rocaCert, X509Certificate.class);
        
        RsaKeyValidator keyValidator = (RsaKeyValidator) KeyValidatorTestUtil.createKeyValidator(RsaKeyValidator.class,
                "rsa-parameter-validation-test-1", "Description", null, -1, null, -1, -1, new Integer[] {});
        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());

        // Do not enable validation of ROCA, everything should pass
        List<String> bitLengths = new ArrayList<String>();
        bitLengths.add("1024");
        bitLengths.add("2048");
        bitLengths.add("2050"); // The positive sample ROCA cert is 2050 bits
        keyValidator.setBitLengths(bitLengths);
        List<String> messages = keyValidator.validate(noroca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());
        messages = keyValidator.validate(roca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());

        // Check for ROCA weak keys
        keyValidator.setPublicKeyModulusDontAllowRocaWeakKeys(true);
        messages = keyValidator.validate(noroca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have been successful: "+messages, 0, messages.size());
        messages = keyValidator.validate(roca.getPublicKey(), null);
        log.trace("Key validation error messages: " + messages);
        assertEquals("Key validation should have failes", 1, messages.size());
        assertEquals("It should have been a ROCA failure.",
                "Invalid: RSA public key modulus is a weak key according to CVE-2017-15361.", messages.get(0));
        
        log.trace("<testRocaWeakKeys()");

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
    
    private static byte[] noRocaCert = Base64
            .decode(("MIIEdDCCA1ygAwIBAgIIVjkVCQFZomowDQYJKoZIhvcNAQEFBQAwNTEWMBQGA1UE"
                    +"AwwNTWFuYWdlbWVudCBDQTEOMAwGA1UECgwFUEstRE0xCzAJBgNVBAYTAkFFMB4X"
                    +"DTE2MDkyMjE1MDgxM1oXDTE2MDkyNDE1MDgxM1owMDEOMAwGA1UEAwwFeG1wcDIx"
                    +"ETAPBgNVBAoMCFByaW1lS2V5MQswCQYDVQQGEwJBRTCBnzANBgkqhkiG9w0BAQEF"
                    +"AAOBjQAwgYkCgYEAlYenj6Yh6/WGDyxpSIFu4p8JUn8Gs0+p8jYwNsdwut0n2jRs"
                    +"92u0ekrmao5C0sdOF3EgVojOAWMGbqA32Q/3skXQqKwapgVlJGJXpNeMm47EwB4z"
                    +"HTFKDwHNrnUOU3EB4kf4Z3leZU1KsDppVyt3he9M1gPHwnhSMKRkdPg64AkCAwEA"
                    +"AaOCAg8wggILMBkGB2eBCAEBBgIEDjAMAgEAMQcTAVATAklEMAwGA1UdEwEB/wQC"
                    +"MAAwHwYDVR0jBBgwFoAUu2ifcFjWKrS4wThm+sPPj8GYatowagYDVR0RBGMwYYgD"
                    +"KQECoBgGCisGAQQBgjcUAgOgCgwIZm9vQGEuc2WgIwYIKwYBBQUHCAWgFwwVdG9t"
                    +"YXNAeG1wcC5kb21haW4uY29toBsGCCsGAQUFBwgHoA8WDV9TZXJ2aWNlLk5hbWUw"
                    +"ggEDBgNVHSAEgfswgfgwKAYDKQECMCEwHwYIKwYBBQUHAgEWE2h0dHBzOi8vZWpi"
                    +"Y2Eub3JnLzIwKAYDKQEDMCEwHwYIKwYBBQUHAgEWE2h0dHBzOi8vZWpiY2Eub3Jn"
                    +"LzMwBQYDKQEBMD0GAykBBDA2MDQGCCsGAQUFBwICMCgeJgBNAHkAIABVAHMAZQBy"
                    +"ACAATgBvAHQAaQBjAGUAIABUAGUAeAB0MFwGAykBBTBVMDAGCCsGAQUFBwICMCQe"
                    +"IgBFAEoAQgBDAEEAIABVAHMAZQByACAATgBvAHQAaQBjAGUwIQYIKwYBBQUHAgEW"
                    +"FWh0dHBzOi8vZWpiY2Eub3JnL0NQUzAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYB"
                    +"BQUHAwQwHQYDVR0OBBYEFMUFBPXfQktUn7WTMUxTHnYSXk8TMA4GA1UdDwEB/wQE"
                    +"AwIF4DANBgkqhkiG9w0BAQUFAAOCAQEAQ1K6zjPjCNFT1+KJ/E959khU/Hg5dObK"
                    +"p4LsS+LpPmFu4M9DjS2vwr48lLh+eBB65U+6/WMTO7/3fEeD3AaoD2+f9pnG6pq9"
                    +"tC3GlfQfuSWELIhebg+73+GcvEpGRqQIKQ0qguTZEJiGK6i7714ECRE+xVD81Hez"
                    +"BE3M3tBSK1Q6zJ36DdgSx99hz0p8IutMX6ntYDWbA1DJ+V3zzCc5zF3ZSogWv3+T"
                    +"CJG3EfrGDJ91eVUlGyfDpHRr9a3WOWbypLjh1Q92xxHOJbvgnS9J6mybaOpQYyCn"
                    +"MVWCdyTMTi9Ik0eybpeVMZYaSEO4xIqwoGbvuBgE2WKm+RuMnMOkfA==").getBytes());

    private static byte[] rocaCert = Base64
            .decode(("MIICpTCCAYwCCQC2u0PIfFaGMjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls"
                    +"b2NhbGhvc3QwHhcNMTcxMDE2MTkzODIxWhcNMTgxMDE2MTkzODIxWjAUMRIwEAYD"
                    +"VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQJZ"
                    +"J7UrpeaMjJJou5IY83ZzYUymVBj0dFsUPNTuU/lJHJoOHC8jqVFjBq/784ZnuHG8"
                    +"DMguYPW7Gp+hWlZxp2XJ8huVh9gBFZZDcqODyIOw3L9sd1cGsx6v8+P9SIVZoIze"
                    +"og+al8TFm2uKjuykV9SoINSVCfdZM2MCvKGjaQsICRgR+Fjy6M6lpiNVrW4EHRk1"
                    +"7aWSibWXaDtz4mV650v/x2Dk1RPMh9uTVZGOqgjTmLvl9oNdyHElIRubNrOgvHC5"
                    +"k6bLP30stAYd5z25cslCrfmVW2/kzZDwDQiK7ASvH17/kfIa9e1EYXx9uAk/lTZt"
                    +"smWAxK85neuU+bFBMFvhAgMBAAEwDQYJKoZIhvcNAQELBQADggECAAG7W49CYRUk"
                    +"YAFRGXu3M85MKOISyc/kkJ8nbHdV6GxJ05FkoDKbcbZ7nncJiIp2VMAMEIP4bRTJ"
                    +"5U4g4vSZlmCs8BDmV3Ts/tbDCM6eqK+2hwjhUnCnmmsLt4xVUeAAsWUHl9AVtjzd"
                    +"oYlm1Kk20QBzNpsvM/gFS5B+duHvTSfELfoq9Pdfvmn2gEXJHe9scO8bfT3fm15z"
                    +"R6AUYsSsxAhup2Rix6jgJ14KGsh6uVm6jhz9aBTBcgx7iMuuP8zUbUE6nryHYXnR"
                    +"cSvuYSesTCoFfnL7elrZDak/n0jLfwUD80aWnReJfu9QQGdqdDnSG8lSQ1XPOC7O"
                    +"/hFW9l0TCzOE").getBytes());

}
