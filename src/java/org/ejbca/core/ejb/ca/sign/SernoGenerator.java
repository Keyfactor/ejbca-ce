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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Implements a singleton serial number generator using SecureRandom. This
 * generator generates random 8 octec (64 bits) serial numbers.
 * 
 * RFC3280 defines serialNumber be positive INTEGER, and X.690 defines INTEGER
 * consist of one or more octets. X.690 also defines as follows:
 * 
 * If the contents octets of an integer value encoding consist of more than one
 * octet, then the bits of the first octet and bit 8 of the second octet: a)
 * shall not all be ones; and b) shall not all be zero.
 * 
 * Therefore, minimum 8 octets value is 0080000000000000 and maximum value is
 * 7FFFFFFFFFFFFFFF."
 * 
 * Therefore, minimum 4 octets value is 00800000 and maximum value is 7FFFFFFF."
 * 
 * X.690:
 * 
 * 8.3 Encoding of an integer value
 * 8.3.1 The encoding of an integer value shall be primitive. The contents octets shall consist of one or more octets.
 * 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet
 * and bit 8 of the second octet:
 * a) shall not all be ones; and
 * b) shall not all be zero.
 * NOTE – These rules ensure that an integer value is always encoded in the smallest possible number of octets.
 * 8.3.3 The contents octets shall be a two's complement binary number equal to the integer value, and consisting of
 * bits 8 to 1 of the first octet, followed by bits 8 to 1 of the second octet, followed by bits 8 to 1 of each octet in turn up to
 * and including the last octet of the contents octets.
 * NOTE – The value of a two's complement binary number is derived by numbering the bits in the contents octets, starting with bit
 * 1 of the last octet as bit zero and ending the numbering with bit 8 of the first octet. Each bit is assigned a numerical value of 2N,
 * where N is its position in the above numbering sequence. The value of the two's complement binary number is obtained by
 * summing the numerical values assigned to each bit for those bits which are set to one, excluding bit 8 of the first octet, and then
 * reducing this value by the numerical value assigned to bit 8 of the first octet if that bit is set to one.
 *
 * @version $Id$
 */
public class SernoGenerator implements ISernoGenerator {
	/** Log4j instance */
	private static Logger log = Logger.getLogger(SernoGenerator.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources
			.getInstance();

	/** random generator algorithm, default SHA1PRNG */
	private String algorithm = "SHA1PRNG";

	/** number of bytes serial number to generate, default 8 */
	private int noOctets = 8;

	/** random generator */
	private SecureRandom random;

	/** A handle to the unique Singleton instance. */
	private static SernoGenerator instance = null;

	/** lowest possible value we should deliver when getSerno is called */
	private BigInteger lowest = new BigInteger("0080000000000000", 16);
	/** highest possible value we should deliver when getSerno is called */
	private BigInteger highest = new BigInteger("7FFFFFFFFFFFFFFF", 16);

	/**
	 * Creates a serial number generator using SecureRandom
	 */
	protected SernoGenerator() throws NoSuchAlgorithmException {
		log.trace(">SernoGenerator()");
		init();
		log.trace("<SernoGenerator()");
	}

	private void init() throws NoSuchAlgorithmException {
		// Init random number generator for random serial numbers
		random = SecureRandom.getInstance(algorithm);

		// Using this seed we should get a different seed every time.
		// We are not concerned about the security of the random bits, only that
		// they are different every time.
		// Extracting 64 bit random numbers out of this should give us 2^32 (4
		// 294 967 296) serialnumbers before
		// collisions (which are seriously BAD), well anyhow sufficient for
		// pretty large scale installations.
		// Design criteria: 1. No counter to keep track on. 2. Multiple threads
		// can generate numbers at once, in
		// a clustered environment etc.
		long seed = Math.abs((new Date().getTime()) + this.hashCode());
		random.setSeed(seed);

		/*
		 * Another possibility is to use SecureRandom's default seeding which is
		 * designed to be secure: <p>The seed is produced by counting the
		 * number of times the VM manages to loop in a given period. This number
		 * roughly reflects the machine load at that point in time. The samples
		 * are translated using a permutation (s-box) and then XORed together.
		 * This process is non linear and should prevent the samples from
		 * "averaging out". The s-box was designed to have even statistical
		 * distribution; it's specific values are not crucial for the security
		 * of the seed. We also create a number of sleeper threads which add
		 * entropy to the system by keeping the scheduler busy. Twenty such
		 * samples should give us roughly 160 bits of randomness. <P> These
		 * values are gathered in the background by a daemon thread thus
		 * allowing the system to continue performing it's different activities,
		 * which in turn add entropy to the random seed. <p> The class also
		 * gathers miscellaneous system information, some machine dependent,
		 * some not. This information is then hashed together with the 20 seed
		 * bytes.
		 */
	}

	/**
	 * Creates (if needed) the serial number generator and returns the object.
	 * 
	 * @return An instance of the serial number generator.
	 */
	public static synchronized ISernoGenerator instance() throws NoSuchAlgorithmException {
		if (instance == null) {
			instance = new SernoGenerator();
		}
		return instance;
	}

	/**
	 * Generates a number of serial number bytes. The number returned should be
	 * a positive number.
	 * 
	 * @return a BigInteger with a new random serial number.
	 */
	public synchronized BigInteger getSerno() {
		// This is only for testing, of size is set to 0 we will generate random number 
		// between 1 and 4, this will give collisions often...
		if (noOctets == 0) {
			Random rand = new Random();
			return new java.math.BigInteger(Long.toString(rand.nextInt(4)));
		}
		
		byte[] sernobytes = new byte[noOctets];
		boolean ok = false;
		BigInteger serno = null;
		while (!ok) {
			random.nextBytes(sernobytes);
			serno = (new java.math.BigInteger(sernobytes)).abs();
			// Must be within the range 0080000000000000 - 7FFFFFFFFFFFFFFF
			if ((serno.compareTo(lowest) >= 0)
					&& (serno.compareTo(highest) <= 0)) {
				ok = true;
			} else {
				String msg = intres
						.getLocalizedMessage("sernogenerator.discarding");
				log.info(msg);
			}
		}
		return serno;
	}

	/**
	 * Returns the number of serial number bytes generated by this generator.
	 * 
	 * @return The number of serial number bytes generated by this generator.
	 */
	public int getNoSernoBytes() {
		return noOctets;
	}

	/**
	 * Sets an optional seed needed by the serno generator. This can be
	 * different things, for a sequential generator it can for instance be the
	 * first number to be generated and for a random generator it can be a
	 * random seed. The constructor may seed the generator enough so this method
	 * may not be nessecary to call.
	 * 
	 * @param seed
	 *            seed used to initilize the serno generator.
	 */
	public void setSeed(long seed) {
		random.setSeed(seed);
	}

	/**
	 * Set the random number algorithm used to something different than the
	 * default SHA1PRNG.
	 * 
	 * @see ISernoGenerator#setAlgorithm(String)
	 */
	public void setAlgorithm(final String algo) throws NoSuchAlgorithmException {
		// Since re-initialization is expensive, we only do it if we changed the algo
		if (this.algorithm == null || !this.algorithm.equals(algo)) {
			this.algorithm = algo;
			// We must re-init after choosing a new algorithm
			init();
		}
	}

	/**
	 * @see ISernoGenerator#setSernoOctetSize(int)
	 */
	public void setSernoOctetSize(final int noOctets) {
		if (this.noOctets != noOctets) {
			if (noOctets == 4) {
				lowest = new BigInteger("00800000", 16);
				highest = new BigInteger("7FFFFFFF", 16);
			}
			if ((noOctets != 4) && (noOctets != 8) && (noOctets != 0)) {
				throw new IllegalArgumentException(
						"SernoOctetSize must be 4 or 8 for this generator.");
			}
			this.noOctets = noOctets;
		}
	}

}
