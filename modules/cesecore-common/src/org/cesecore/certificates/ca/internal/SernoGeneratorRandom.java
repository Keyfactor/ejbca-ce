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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;

/**
 * Implements a singleton serial number generator using SecureRandom. This generator generates random 8 octec (64 bits) serial numbers.
 * 
 * RFC3280 defines serialNumber be positive INTEGER, and X.690 defines INTEGER consist of one or more octets. X.690 also defines as follows:
 * 
 * If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
 * a) shall not all be ones; and b) shall not all be zero.
 * 
 * Therefore, minimum 8 octets value is 0080000000000000 and maximum value is 7FFFFFFFFFFFFFFF."
 * 
 * Therefore, minimum 4 octets value is 00800000 and maximum value is 7FFFFFFF."
 * 
 * X.690:
 * 
 * 8.3 Encoding of an integer value 8.3.1 The encoding of an integer value shall be primitive. The contents octets shall consist of one or more
 * octets. 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the
 * second octet: a) shall not all be ones; and b) shall not all be zero. NOTE – These rules ensure that an integer value is always encoded in the
 * smallest possible number of octets. 8.3.3 The contents octets shall be a two's complement binary number equal to the integer value, and consisting
 * of bits 8 to 1 of the first octet, followed by bits 8 to 1 of the second octet, followed by bits 8 to 1 of each octet in turn up to and including
 * the last octet of the contents octets. NOTE – The value of a two's complement binary number is derived by numbering the bits in the contents
 * octets, starting with bit 1 of the last octet as bit zero and ending the numbering with bit 8 of the first octet. Each bit is assigned a numerical
 * value of 2N, where N is its position in the above numbering sequence. The value of the two's complement binary number is obtained by summing the
 * numerical values assigned to each bit for those bits which are set to one, excluding bit 8 of the first octet, and then reducing this value by the
 * numerical value assigned to bit 8 of the first octet if that bit is set to one.
 * 
 * @version $Id$
 */
public class SernoGeneratorRandom implements SernoGenerator {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(SernoGeneratorRandom.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** random generator algorithm, default SHA1PRNG */
    private String algorithm = "SHA1PRNG";

    /** number of bytes serial number to generate, default value taken from CesecoreConfiguration */
    private int noOctets = Integer.parseInt(CesecoreConfiguration.DEFAULT_SERIAL_NUMBER_OCTET_SIZE_NEWCA); 

    /** random generator */
    private SecureRandom random;

    /** A handle to the unique Singleton instance. */
    private static SernoGeneratorRandom instance = null;

    /** lowest possible value we should deliver when getSerno is called */
    private BigInteger lowest = new BigInteger("0080000000000000000000000000000000000000", 16); // Default value for 160 bit serials
    /** highest possible value we should deliver when getSerno is called */
    private BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16); // Default value for 160 bit serials

    /**
     * Creates a serial number generator using SecureRandom
     */
    protected SernoGeneratorRandom() {
        if (log.isTraceEnabled()) {
            log.trace(">SernoGenerator()");
        }
        this.algorithm = CesecoreConfiguration.getCaSerialNumberAlgorithm();
        setSernoOctetSize(CesecoreConfiguration.getSerialNumberOctetSizeForNewCa());
        init();
        if (log.isTraceEnabled()) {
            log.trace("<SernoGenerator()");
        }
    }

    private void init() {
        // Init random number generator for random serial numbers. 
        // SecureRandom provides a cryptographically strong random number generator (RNG).
        try {
            // Use a specified algorithm if ca.rngalgorithm is provided and it's not set to default
            if (!StringUtils.isEmpty(algorithm) && !StringUtils.containsIgnoreCase(algorithm, "default")) {
                random = SecureRandom.getInstance(algorithm);
                log.info("Using "+algorithm+" serialNumber RNG algorithm.");
            } else if (!StringUtils.isEmpty(algorithm) && StringUtils.equalsIgnoreCase(algorithm, "defaultstrong")) {
                // If defaultstrong is specified and we use >=JDK8 try the getInstanceStrong to get a guaranteed strong random number generator.
                // Note that this may give you a generator that takes >30 seconds to create a single random number. 
                // On JDK8/Linux this gives you a NativePRNGBlocking, while SecureRandom.getInstance() gives a NativePRNG.
                try {
                    final Method methodGetInstanceStrong = SecureRandom.class.getDeclaredMethod("getInstanceStrong");
                    random = (SecureRandom) methodGetInstanceStrong.invoke(null);
                    log.info("Using SecureRandom.getInstanceStrong() with " + random.getAlgorithm() + " for serialNumber RNG algorithm.");
                } catch (NoSuchMethodException | SecurityException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                    throw new IllegalStateException("SecureRandom.getInstanceStrong() is not available or failed invocation. (This method was added in Java 8.)");
                }
            } else if (!StringUtils.isEmpty(algorithm) && StringUtils.equalsIgnoreCase(algorithm, "default")) {
                // We entered "default" so let's use a good default SecureRandom this should be good enough for just about everyone (on Linux at least)
                // On Linux the default Java implementation uses the (secure) /dev/(u)random, but on windows something else
                // On JDK8/Linux this gives you a NativePRNG, while SecureRandom.getInstanceStrong() gives a NativePRNGBlocking.
                random = new SecureRandom();
                log.info("Using default " + random.getAlgorithm() + " serialNumber RNG algorithm.");
            }
        } catch (NoSuchAlgorithmException e) {
            //This state is unrecoverable, and since algorithm is set in configuration requires a redeploy to handle
            throw new IllegalStateException("Algorithm " + algorithm + " was not a valid algorithm.", e);
        }
        if (random == null) {
            //This state is unrecoverable, and since algorithm is set in configuration requires a redeploy to handle
            throw new IllegalStateException("Algorithm " + algorithm + " was not a valid algorithm.");
        }
        // Call nextBytes directly after in order to force seeding if not already done. SecureRandom typically seeds on first call.
        random.nextBytes(new byte[20]);
    }

    /**
     * Creates (if needed) the serial number generator and returns the object.
     * 
     * @return An instance of the serial number generator.
     */
    public static synchronized SernoGenerator instance() {
        if (instance == null) {
            instance = new SernoGeneratorRandom();
        }
        return instance;
    }

    @Override
    public synchronized BigInteger getSerno() {
        // This is only for testing, of size is set to 0 we will generate random number
        // between 1 and 4, this will give collisions often...
        if (noOctets == 0) {
            Random rand = new Random();
            return new java.math.BigInteger(Long.toString(rand.nextInt(4)));
        }

        final byte[] sernobytes = new byte[noOctets];
        boolean ok = false;
        BigInteger serno = null;
        while (!ok) {
            random.nextBytes(sernobytes);
            serno = (new java.math.BigInteger(sernobytes)).abs();
            // Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
            if (checkSernoValidity(serno)) {
                ok = true;
            } else {
                String msg = intres.getLocalizedMessage("sernogenerator.discarding");
                log.info(msg);
            }
        }
        return serno;
    }

    protected boolean checkSernoValidity(final BigInteger serno) {
        if ((serno.compareTo(lowest) >= 0) && (serno.compareTo(highest) <= 0)) {
            return true;
        }
        return false;
    }

    @Override
    public int getNoSernoBytes() {
        return noOctets;
    }

    @Override
    public void setSeed(final long seed) {
        random.setSeed(seed);
    }

    @Override
    public void setAlgorithm(final String algo) throws NoSuchAlgorithmException {
        // Since re-initialization is expensive, we only do it if we changed the algo
        if (this.algorithm == null || !this.algorithm.equals(algo)) {
            this.algorithm = algo;
            // We must force re-init after choosing a new algorithm
            this.random = null;
            init();
        }
    }

    /** Available for testing so we can compare that we actually use what we think 
     * @return the random generator algorithm as reported by the underlying Java random number generator.
     */
    protected String getAlgorithm() {
        return random.getAlgorithm();
    }
    
    @Override
    public void setSernoOctetSize(final int noOctets) {
        if (this.noOctets != noOctets) {
        	// We allow 0 octets for testing
            if ((noOctets > 20) && (noOctets != 0)) {
                throw new IllegalArgumentException("SernoOctetSize must be between 4 and 20 bytes for this generator.");
            }
            char[] arr = new char[noOctets*2];
            // 00800000 (filled with 0 to the no of octets)
            Arrays.fill(arr, '0');
            arr[2] = '8';
            lowest = new BigInteger(String.valueOf(arr), 16);
            // 7FFFFFFF (filled with F to the no of octets)
            Arrays.fill(arr, 'F');
            arr[0] = '7';
            highest = new BigInteger(String.valueOf(arr), 16);
            this.noOctets = noOctets;
        }
    }

}
