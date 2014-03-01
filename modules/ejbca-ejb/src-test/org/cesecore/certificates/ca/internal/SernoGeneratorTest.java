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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.junit.Test;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id$
 */
public class SernoGeneratorTest {
//    private static final Logger log = Logger.getLogger(SernoGeneratorTest.class);

    /** Test min and max values for different serial number sizes. */
    @Test
    public void testSernoValidationChecker() throws NoSuchAlgorithmException {
        // Default serno size 8 bytes (64 bits)
        SernoGeneratorRandom gen = new SernoGeneratorRandom();
        BigInteger lowest = new BigInteger("0080000000000000", 16);
        BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        BigInteger toolow = new BigInteger("007FFFFFFFFFFFFF", 16);
        BigInteger toohigh = new BigInteger("8000000000000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));

        // Set serno size 4 bytes (32 bits)
        gen.setSernoOctetSize(4);
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
        // Set serno size 20 bytes (160 bits)
        gen.setSernoOctetSize(20);
        lowest = new BigInteger("0080000000000000000000000000000000000000", 16);
        highest = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        assertTrue(gen.checkSernoValidity(lowest));
        assertTrue(gen.checkSernoValidity(highest));
        toolow = new BigInteger("007FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);
        toohigh = new BigInteger("8000000000000000000000000000000000000000", 16);
        assertFalse(gen.checkSernoValidity(toolow));
        assertFalse(gen.checkSernoValidity(toohigh));
    }
    
    @Test
    public void test01GenerateSernos8Octets() throws Exception {
        SernoGenerator gen = SernoGeneratorRandom.instance();
        HashMap<String, String> map = new HashMap<String, String>(500000);
        String hex = null;

        for (int j = 0; j < 500; j++) {
            for (int i = 1; i < 1001; i++) {
                BigInteger bi = gen.getSerno();

                //hex = Hex.encode(serno);
                hex = bi.toString(16);

                if (map.put(hex, hex) != null) {
//                    log.warn("Duplicate serno produced: " + hex);
//                    log.warn("Number of sernos produced before duplicate: "+(j*1000+i));
                    assertTrue("Duplicate serno produced after "+(j*1000+i)+" sernos.", false);
                }
            }

            //log.debug(((j + 1) * 1000) + " sernos produced: " + hex);

            //long seed = Math.abs((new Date().getTime()) + this.hashCode());
            //gen.setSeed(seed);
            //log.debug("Reseeding: " + seed);
        }

//        log.info("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
//        log.info("Number of duplicates: "+duplicates);
    }
    
    /** Using only 32 bit serial numbers will produce collisions 
     * about 1-5 times for 100.000 serial numbers
     */
    @Test
    public void test02GenerateSernos4Octets() throws Exception {
        SernoGenerator gen = SernoGeneratorRandom.instance();
        gen.setSernoOctetSize(4);
        gen.setAlgorithm("SHA1PRNG");
        HashMap<String, String> map = new HashMap<String, String>(100000);
        String hex = null;

        int duplicates = 0;
        for (int j = 0; j < 100; j++) {
            for (int i = 1; i < 1001; i++) {
                BigInteger bi = gen.getSerno();

                //hex = Hex.encode(serno);
                hex = bi.toString(16);

                if (map.put(hex, hex) != null) {
                	duplicates++;
//                    log.warn("Duplicate serno produced: " + hex);
//                    log.warn("Number of sernos produced before duplicate: "+(j*1000+i));
                    if (duplicates > 10) {
                        assertTrue("More then 10 duplicates produced, "+duplicates, false);                    	
                    }
                }
            }

        }

//        log.info("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
//        log.info("Number of duplicates: "+duplicates);
    }

}
