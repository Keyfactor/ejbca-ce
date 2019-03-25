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
package org.cesecore.certificates.ca.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.HashMap;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Integer;
import org.junit.Test;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id$
 */
public class SernoGeneratorTest {
    private static final Logger log = Logger.getLogger(SernoGeneratorTest.class);

    /** Test min and max values for different serial number sizes. */
    @Test
    public void testSernoValidationChecker() throws NoSuchAlgorithmException {
        // Default serno size 20 bytes (160 bits)
        SernoGeneratorRandom gen = new SernoGeneratorRandom(20);
        BigInteger lowest = new BigInteger("0080000000000000000000000000000000000000", 16);
        BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        BigInteger toolow = new BigInteger("007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger toohigh = new BigInteger("8000000000000000000000000000000000000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));

        // Default serno size 16 bytes (128 bits)
        gen = new SernoGeneratorRandom(16);
        lowest = new BigInteger("00800000000000000000000000000000", 16);
        highest = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        toolow = new BigInteger("007FFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        toohigh = new BigInteger("80000000000000000000000000000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));

        // Set serno size 4 bytes (32 bits)
        gen = new SernoGeneratorRandom(4);
        lowest = new BigInteger("00800000", 16);
        highest = new BigInteger("7FFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        toolow = new BigInteger("007FFFFF", 16);
        toohigh = new BigInteger("80000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));
        BigInteger someSerno = new BigInteger("605725c", 16);
        assertEquals(1, someSerno.compareTo(lowest));
        assertEquals(-1, someSerno.compareTo(highest));
        assertTrue(gen.checkSernoValidity(someSerno));
        
        // Set serno size 8 bytes (64 bits)
        gen = new SernoGeneratorRandom(8);
        lowest = new BigInteger("0080000000000000", 16);
        highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        toolow = new BigInteger("007FFFFFFFFFFFFF", 16);
        toohigh = new BigInteger("8000000000000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));
    }

    /** Test certificate serialNumber generation with 8 octets size (64 bits). 
     * Using 64 bit serial numbers should not product any collisions for 500.000 serials
     */
    @Test
    public void testGenerateSernos8OctetsSHA1PRNG() throws Exception {
        final long start = System.currentTimeMillis();
        final int noRounds = 500;
        generateSernos(8, "SHA1PRNG", 0, noRounds);
        final long end = System.currentTimeMillis();
        final String algo = ((SernoGeneratorRandom)SernoGeneratorRandom.instance(8)).getAlgorithm();
        assertEquals("SHA1PRNG", algo);
        BigDecimal time = BigDecimal.valueOf(end-start);
        BigDecimal div = time.divide(BigDecimal.valueOf(500000));
        log.info("Creating "+noRounds*1000+" 8 octet serNos with "+algo+" took "+(end-start)+" ms, thats "+div+" ms per serno");
    }
    
    /** Using only 32 bit serial numbers will produce collisions 
     * about 1-5 times for 100.000 serial numbers
     */
    @Test
    public void testGenerateSernos4OctetsSHA1PRNG() throws Exception {
        final long start = System.currentTimeMillis();
        final int noRounds = 100;
        generateSernos(4, "SHA1PRNG", 10, noRounds);
        final long end = System.currentTimeMillis();
        final String algo = ((SernoGeneratorRandom)SernoGeneratorRandom.instance(4)).getAlgorithm();
        assertEquals("SHA1PRNG", algo);
        BigDecimal time = BigDecimal.valueOf(end-start);
        BigDecimal div = time.divide(BigDecimal.valueOf(500000));
        log.info("Creating "+noRounds*1000+" 4 octet serNos with "+algo+" took "+(end-start)+" ms, thats "+div+" ms per serno");
    }
    
    /** Test certificate serialNumber generation with 20 octets size (160 bits). 
     * Using 160 bit serial numbers should not product any collisions for 500.000 serials
     */
    @Test
    public void testGenerateSernos20OctetsSHA1PRNG() throws Exception {
        final long start = System.currentTimeMillis();
        final int noRounds = 500;
        generateSernos(20, "SHA1PRNG", 0, noRounds);
        final long end = System.currentTimeMillis();
        final String algo = ((SernoGeneratorRandom)SernoGeneratorRandom.instance(20)).getAlgorithm();
        assertEquals("SHA1PRNG", algo);
        BigDecimal time = BigDecimal.valueOf(end-start);
        BigDecimal div = time.divide(BigDecimal.valueOf(500000));
        log.info("Creating "+noRounds*1000+" 8 octet serNos with "+algo+" took "+(end-start)+" ms, thats "+div+" ms per serno");
    }


    /** Try fetching a random number generator of type "defaultstrong". 
     * We will not make actual tests with this, since on Tomas's Linux laptop (on real HW) 
     * it takes 30-70 seconds to generate a single random number once the entropy pool is exhausted after 0-10 serials.
     * On JDK7 and less the "defaultstrong" option is not available, which is considered in this test.
     */
    @Test
    public void testGettingDefaultStrong() throws Exception {
        try {
            generateSernos(4, "defaultstrong", 0, 0);
            // If running on JDK >= 8 we will come here
            final String algo = ((SernoGeneratorRandom)SernoGeneratorRandom.instance(4)).getAlgorithm();
            assertEquals("NativePRNGBlocking", algo);        
        } catch (IllegalStateException e) {
            // if running on JDK < 8 this is a valid exception
            try {
                SecureRandom.class.getDeclaredMethod("getInstanceStrong");
                // What? We had an IllegalStateException but running on JDK >= 8?
                fail("We couldn't get the 'defaultstrong' algorithm although we appear to run on JDK >=8: "+e.getMessage());
            } catch (NoSuchMethodException nsme) {
                // Yep, this JDK didn't have SecureRandom.getInstanceStrong(), so let it pass
                log.debug("Trying to get SecureRandom.getInstanceStrong() on JDK < 8 resulted in an IllegalStateException, as expected");
                assumeTrue("Test is only relevant on Java 8.", false);
            }
        }
    }

    /** Try fetching a random number generator of type "default". This will create a default SecureRandom implementation. 
     */
    @Test
    public void testGenerateSernos8OctetsDefault() throws Exception {
        final long start = System.currentTimeMillis();
        final int noRounds = 500;
        generateSernos(8, "default", 0, noRounds);
        final long end = System.currentTimeMillis();
        final String algo = ((SernoGeneratorRandom)SernoGeneratorRandom.instance(8)).getAlgorithm();
        assertEquals("NativePRNG", algo);            
        BigDecimal time = BigDecimal.valueOf(end-start);
        BigDecimal div = time.divide(BigDecimal.valueOf(500000));
        log.info("Creating "+noRounds*1000+" 8 octet serNos with "+algo+" took "+(end-start)+" ms, thats "+div+" ms per serno");
    }
    
    private void generateSernos(final int nrOctets, final String algorithm, final int maxDups, final int roundsOf1000) throws Exception {
        // this will actually create a default RNG first (depending on configuration in cesecore.properties), which will be changed by setAlgorithm below
        SernoGenerator gen = SernoGeneratorRandom.instance(nrOctets);
        gen.setAlgorithm(algorithm);
        HashMap<String, String> map = new HashMap<String, String>(100000);
        String hex = null;

        int duplicates = 0;
        for (int j = 0; j < roundsOf1000; j++) {
            for (int i = 1; i < 1001; i++) {
                //long start = System.currentTimeMillis();
                BigInteger bi = gen.getSerno();
                //long end = System.currentTimeMillis();
                //log.info("Generated one serno took (ms): "+(end-start));
                
                // Check that it generates the specified number of ASN.1 encoded integers
                // The length to check is nrOctets+2 since it is encoded as "tag+length+value", where tag and length are 1 octet each
                ASN1Integer asn1 = new ASN1Integer(bi);
                assertEquals("Encoded ASN.1 integer length should be nrOctets + 2 (tag+length+value)", nrOctets+2, asn1.getEncoded().length);

                //hex = Hex.encode(serno);
                hex = bi.toString(16);

                if (map.put(hex, hex) != null) {
                	duplicates++;
//                    log.warn("Duplicate serno produced: " + hex);
//                    log.warn("Number of sernos produced before duplicate: "+(j*1000+i));
                    if (duplicates > maxDups) {
                        assertTrue("More then 10 duplicates produced, "+duplicates, false);                    	
                    }
                }
            }

        }
//        log.info("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
//        log.info("Number of duplicates: "+duplicates);
    }

    public static Throwable threadException = null;
    @Test
    public void testMultiThreadedSernoGeneration() throws Exception {
        Thread no1 = new Thread(new SernoTester(4),"4 octets"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no2 = new Thread(new SernoTester(8),"8 octets"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no3 = new Thread(new SernoTester(12),"12 octets"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no4 = new Thread(new SernoTester(16),"16 octets"); // NOPMD we want to use thread here, it's not a JEE app
        Thread no5 = new Thread(new SernoTester(20),"20 octets"); // NOPMD we want to use thread here, it's not a JEE app
        CacheExceptionHandler handler = new CacheExceptionHandler();
        no1.setUncaughtExceptionHandler(handler);
        no2.setUncaughtExceptionHandler(handler);
        no3.setUncaughtExceptionHandler(handler);
        no4.setUncaughtExceptionHandler(handler);
        no5.setUncaughtExceptionHandler(handler);
        long start = new Date().getTime();
        no1.start();
        log.info("Started no1");
        no2.start();
        log.info("Started no2");
        no3.start();
        log.info("Started no3");
        no4.start();
        log.info("Started no4");
        no5.start();
        log.info("Started no5");
        no1.join();
        no2.join();
        no3.join();
        no4.join();
        no5.join();
        long end = new Date().getTime();
        log.info("Time consumed: "+(end-start));
        if (threadException != null) {
            throw new IllegalStateException(threadException);
        }
    }

    private static class SernoTester implements Runnable { // NOPMD, this is not a JEE app, only a test
        private int noOctets;
        public SernoTester(int noOctets) {
            this.noOctets = noOctets;
        }
        public void run() {
            for (int i=0; i<100000;i++) {
                SernoGenerator gen = SernoGeneratorRandom.instance(noOctets);
                BigInteger bi = gen.getSerno();
                ASN1Integer asn1 = new ASN1Integer(bi);
                try {
                    assertEquals("Multi-threaded test encoded length failure, is the wrong generator returned?", noOctets+2, asn1.getEncoded().length);
                } catch (IOException e) {
                    log.error("IOEsception encoding ASN.1: ", e);
                    fail("IOEsception encoding ASN.1: " + e.getMessage());
                }
            }
        }
    }
    private static class CacheExceptionHandler implements Thread.UncaughtExceptionHandler {
        public void uncaughtException(Thread t, Throwable e) { // NOPMD, this is not a JEE app, only a test
            SernoGeneratorTest.threadException = e;
        }
    }


}
