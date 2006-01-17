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
import java.util.Date;
import java.util.HashMap;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.sign.ISernoGenerator;
import org.ejbca.core.ejb.ca.sign.SernoGenerator;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id: TestSernoGenerator.java,v 1.2 2006-01-17 20:33:58 anatom Exp $
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

    /* Generates many serial numbers...
    */
    public void test01GenerateSernos() throws Exception {
        log.debug(">test01GenerateSernos()");

        ISernoGenerator gen = SernoGenerator.instance();
        HashMap map = new HashMap(300000);
        String hex = null;

        for (int j = 0; j < 300; j++) {
            for (int i = 0; i < 1000; i++) {
                BigInteger bi = gen.getSerno();

                //hex = Hex.encode(serno);
                hex = bi.toString();

                if (map.put(hex, hex) != null) {
                    System.out.println("Duplicate serno produced: " + hex);
                }
            }

            System.out.println(((j + 1) * 1000) + " sernos produced: " + hex);

            long seed = Math.abs((new Date().getTime()) + this.hashCode());
            gen.setSeed(seed);
            System.out.println("Reseeding: " + seed);
        }

        System.out.println("Map now contains " + map.size() + " serial numbers.");
        log.debug("<test01GenerateSernos()");
    }
}
