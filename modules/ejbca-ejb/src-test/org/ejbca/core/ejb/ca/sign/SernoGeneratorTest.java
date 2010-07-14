/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.sign;

import java.math.BigInteger;
import java.util.HashMap;

import junit.framework.TestCase;

import org.apache.log4j.Logger;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id$
 */
public class SernoGeneratorTest extends TestCase {
    private static final Logger log = Logger.getLogger(SernoGeneratorTest.class);

    /**
     * Creates a new TestSernoGenerator object.
     *
     * @param name name
     */
    public SernoGeneratorTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    public void test01GenerateSernos8Octets() throws Exception {
        log.trace(">test01GenerateSernos8Octets()");

        ISernoGenerator gen = SernoGenerator.instance();
        HashMap map = new HashMap(500000);
        String hex = null;

        int duplicates = 0;
        for (int j = 0; j < 500; j++) {
            for (int i = 1; i < 1001; i++) {
                BigInteger bi = gen.getSerno();

                //hex = Hex.encode(serno);
                hex = bi.toString(16);

                if (map.put(hex, hex) != null) {
                	duplicates++;
                    log.warn("Duplicate serno produced: " + hex);
                    log.warn("Number of sernos produced before duplicate: "+(j*1000+i));
                    assertTrue(false);
                }
            }

            //log.debug(((j + 1) * 1000) + " sernos produced: " + hex);

            //long seed = Math.abs((new Date().getTime()) + this.hashCode());
            //gen.setSeed(seed);
            //log.debug("Reseeding: " + seed);
        }

        log.info("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
        log.info("Number of duplicates: "+duplicates);
        log.trace("<test01GenerateSernos8Octets()");
    }
    
    /** Using only 32 bit serial numbers will produce collisions 
     * about 1-5 times for 100.000 serial numbers
     */
    public void test02GenerateSernos4Octets() throws Exception {
        log.trace(">test01GenerateSernos4Octets()");

        ISernoGenerator gen = SernoGenerator.instance();
        gen.setSernoOctetSize(4);
        gen.setAlgorithm("SHA1PRNG");
        HashMap map = new HashMap(100000);
        String hex = null;

        int duplicates = 0;
        for (int j = 0; j < 100; j++) {
            for (int i = 1; i < 1001; i++) {
                BigInteger bi = gen.getSerno();

                //hex = Hex.encode(serno);
                hex = bi.toString(16);

                if (map.put(hex, hex) != null) {
                	duplicates++;
                    log.warn("Duplicate serno produced: " + hex);
                    log.warn("Number of sernos produced before duplicate: "+(j*1000+i));
                    //assertTrue(false);
                }
            }

        }

        log.info("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
        log.info("Number of duplicates: "+duplicates);
        log.trace("<test02GenerateSernos4Octets()");
    }

}
