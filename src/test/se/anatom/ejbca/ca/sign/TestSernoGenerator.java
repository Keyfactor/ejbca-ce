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

package se.anatom.ejbca.ca.sign;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.sign.ISernoGenerator;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id: TestSernoGenerator.java,v 1.3 2008-02-06 12:31:07 anatom Exp $
 */
public class TestSernoGenerator extends TestCase {
    private static Logger log = Logger.getLogger(TestSernoGenerator.class);

    /**
     * Creates a new TestSernoGenerator object.
     *
     * @param name name
     */
    public TestSernoGenerator(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

    public void test01GenerateSernos8Octets() throws Exception {
        log.debug(">test01GenerateSernos8Octets()");

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
                    System.out.println("Warning!");
                    System.out.println("Duplicate serno produced: " + hex);
                    System.out.println("Warning!");
                    System.out.println("Number of sernos produced before duplicate: "+(j*1000+i));
                    assertTrue(false);
                }
            }

            //System.out.println(((j + 1) * 1000) + " sernos produced: " + hex);

            //long seed = Math.abs((new Date().getTime()) + this.hashCode());
            //gen.setSeed(seed);
            //System.out.println("Reseeding: " + seed);
        }

        System.out.println("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
        System.out.println("Number of duplicates: "+duplicates);
        log.debug("<test01GenerateSernos8Octets()");
    }
    
    /** Using only 32 bit serial numbers will produce collisions 
     * about 1-5 times for 100.000 serial numbers
     */
    public void test02GenerateSernos4Octets() throws Exception {
        log.debug(">test01GenerateSernos4Octets()");

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
                    System.out.println("Warning!");
                    System.out.println("Duplicate serno produced: " + hex);
                    System.out.println("Warning!");
                    System.out.println("Number of sernos produced before duplicate: "+(j*1000+i));
                    //assertTrue(false);
                }
            }

        }

        System.out.println("Map now contains " + map.size() + " serial numbers. Last one: "+hex);
        System.out.println("Number of duplicates: "+duplicates);
        log.debug("<test02GenerateSernos4Octets()");
    }

}
