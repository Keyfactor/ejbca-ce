package se.anatom.ejbca.ca.sign.junit;

import java.math.BigInteger;
import java.util.*;

import org.apache.log4j.Logger;

import junit.framework.*;

import se.anatom.ejbca.ca.sign.*;


/**
 * Tests generation of serial numbers.
 *
 * @version $Id: TestSernoGenerator.java,v 1.7 2003-07-24 08:43:30 anatom Exp $
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
