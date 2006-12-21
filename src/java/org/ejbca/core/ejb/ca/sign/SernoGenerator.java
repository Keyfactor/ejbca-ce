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
import java.security.SecureRandom;
import java.util.Date;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;


/**
 * Implements a singleton serial number generator using SecureRandom.
 * This generator generates random 8 octec (64 bits) serial numbers.
 * 
 * RFC3280 defines serialNumber be positive INTEGER, and X.690 defines
 * INTEGER consist of one or more octets. X.690 also defines as follows:
 *
 * If the contents octets of an integer value encoding consist of more than
 * one octet, then the bits of the first octet and bit 8 of the second
 * octet:
 *  a) shall not all be ones; and
 *  b) shall not all be zero.
 *
 * Therefore, minimum 8 octets value is 0080000000000000 and maximum value
 * is 7FFFFFFFFFFFFFFF."
 *
 * @version $Id: SernoGenerator.java,v 1.6 2006-12-21 15:55:55 anatom Exp $
 */
public class SernoGenerator implements ISernoGenerator {
    /** Log4j instance */
    private static Logger log = Logger.getLogger(SernoGenerator.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** random generator algorithm */
    private static String algorithm = "SHA1PRNG";
    
    /** random generator */
    private SecureRandom random;

    /** A handle to the unique Singleton instance. */
    private static SernoGenerator instance = null;

    private static final BigInteger lowest = new BigInteger("0080000000000000", 16);
    private static final BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);

    /**
     * Creates a serialn number generator using SecureRandom
     */
    protected SernoGenerator() throws Exception {
        log.debug(">SernoGenerator()");

        // Init random number generator for random serialnumbers
        random = SecureRandom.getInstance(algorithm);

        // Using this seed we should get a different seed every time.
        // We are not concerned about the security of the random bits, only that they are different every time.
        // Extracting 64 bit random numbers out of this should give us 2^32 (4 294 967 296) serialnumbers before
        // collisions (which are seriously BAD), well anyhow sufficient for pretty large scale installations.
        // Design criteria: 1. No counter to keep track on. 2. Multiple threads can generate numbers at once, in
        // a clustered environment etc.
        long seed = Math.abs((new Date().getTime()) + this.hashCode());
        random.setSeed(seed);

        /* Another possibility is to use SecureRandom's default seeding which is designed to be secure:
        * <p>The seed is produced by counting the number of times the VM
        * manages to loop in a given period. This number roughly
        * reflects the machine load at that point in time.
        * The samples are translated using a permutation (s-box)
        * and then XORed together. This process is non linear and
        * should prevent the samples from "averaging out". The s-box
        * was designed to have even statistical distribution; it's specific
        * values are not crucial for the security of the seed.
        * We also create a number of sleeper threads which add entropy
        * to the system by keeping the scheduler busy.
        * Twenty such samples should give us roughly 160 bits of randomness.
        * <P> These values are gathered in the background by a daemon thread
        * thus allowing the system to continue performing it's different
        * activites, which in turn add entropy to the random seed.
        * <p> The class also gathers miscellaneous system information, some
        * machine dependent, some not. This information is then hashed together
        * with the 20 seed bytes. */
        log.debug("<SernoGenerator()");
    }

    /**
     * Creates (if needed) the serial number generator and returns the object.
     *
     * @return An instance of the serial number generator.
     */
    public static synchronized ISernoGenerator instance()
        throws Exception {
        if (instance == null) {
            instance = new SernoGenerator();
        }
        return instance;
    }

    /**
     * Generates a number of serial number bytes. The number returned should be a positive number.
     *
     * @return a BigInteger with a new random serial number.
     */
    public synchronized BigInteger getSerno() {
        byte[] sernobytes = new byte[8];
        boolean ok = false;
        BigInteger serno = null;
        while (!ok) {
            random.nextBytes(sernobytes);
            serno = (new java.math.BigInteger(sernobytes)).abs();
            // Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
            if ( (serno.compareTo(lowest) >= 0) && (serno.compareTo(highest) <= 0) ) {
                ok = true;
            } else {
                String msg = intres.getLocalizedMessage("sernogenerator.discarding");        	
                log.info(msg);
            }
        }
        return serno;
    }

    /**
     * Returns the number of serial number byutes generated by this generator.
     *
     * @return The number of serial number byutes generated by this generator.
     */
    public int getNoSernoBytes() {
        return 8;
    }

    /**
     * Sets an optional seed needed by the serno generator. This can be different things, for a
     * sequential generator it can for instance be the first number to be generated and for a
     * random generator it can be a random seed. The constructor may seed the generator enough so
     * this method may not be nessecary to call.
     *
     * @param seed seed used to initilize the serno generator.
     */
    public void setSeed(long seed) {
        random.setSeed(seed);
    }
    
    /** 
     * Set the random number algorithm used to something different than the default SHA1PRNG.
     */
     public static void setAlgorithm(String algo) {
         algorithm = algo;
     }
}
