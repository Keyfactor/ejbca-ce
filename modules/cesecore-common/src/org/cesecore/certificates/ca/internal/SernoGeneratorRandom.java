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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandom;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.util.Strings;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;

/**
 * This is a "constant octet size random serial number generator".
 * (note that this generator is not designed to generated a specified level of entropy, although the entropy will be fixed and can easily calculated according to the below rules.)
 * 
 * The purpose of this certificate serial number generator is to generate random serial numbers with a fixed octet size. If you specify the octet size 
 * to be 8 octets, the serial number will be 8 octets, if you specify 20 octets it will be 20 octets, etc.
 * To achieve this the following process is performed:
 * 
 * - The specified number of octets is retrieved from a CSPRNG (SecureRandom).
 * - The octets are converted into a positive BigInteger (serial numbers are ASN.1 INTEGERs) by taking the absolute value of the BigInteger 
 *   created from the random bytes 
 * - If this integer does not fulfill requirements and limitations specified by RFC5280 and X.690, the serial number is discarded
 * - This process is repeated with new octets from the CSPRNG until an integer fulfilling the tests has been retrieved.
 * -- This integer is returned as the serial number from the generator 
 * 
 * RFC 5280 defines serialNumber be a positive INTEGER.
 * 
 * Simply using an integer conforming to RFC5280 will lead to variable length encoding of the serial number in the certificate. 
 * If the (random) integer 3 is retrieved from the CSPRNG it will be encoded as '03' and the number 65535 as 'FFFF', etc. Also if the number is too 
 * large, ASN.1 integers being in two-complement representation, it will be encoded as 9 bytes.
 * 
 * To achieve fixed octet length serials we apply restrictions according to X.690. X.690 defines that INTEGER consist of one or more octets,
 * and also defines as follows:
 *   If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
 *   a) shall not all be ones; and b) shall not all be zero.
 * This sets minimum and maximum boundaries for the integer.
 *   Minimum 4 octets value is 00800000 and maximum value is 7FFFFFFF."
 *   Minimum 8 octets value is 0080000000000000 and maximum value is 7FFFFFFFFFFFFFFF."
 * Simply extend with '00' and 'FF' for other octet sizes. 
 * 
 * X.690:
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

    /** RFC5280, section 4.1.2.2, specifies using max 20 octets for serial number */ 
    private static final int SERNO_MAX_LENGTH = 20;

    /** random generator algorithm, defaults to FIPS approve SHA1PRNG in constructor 
     * The algorithm is specified globally in CesecoreConfiguration.getCaSerialNumberAlgorithm() */
    private String algorithm;

    /** number of bytes to generate, fixed size serial numbers */
    private int noOctets;

    /** random generator */
    private SecureRandom random;

    /** A registry of Singleton instances, to handle multiple octet sizes simultaneously. */
    private static Map<Integer, SernoGeneratorRandom> instances = new HashMap<>();
    /**
     * Creates (if needed) a serial number generator and returns the object.
     *
     * @return An instance of the serial number generator.
     */
    public static synchronized SernoGenerator instance(Integer noOctets) {
        SernoGeneratorRandom instance = instances.get(noOctets);
        if (instance == null) {
            instance = new SernoGeneratorRandom(noOctets);
            instances.put(noOctets, instance);
        }
        return instance;
    }

    /** DO NOT USE: Protected only to do testing of this implementation
     * use {@link #instance(Integer)} instead
     */
    protected SernoGeneratorRandom(Integer noOctets) {
        if (log.isTraceEnabled()) {
            log.trace(">SernoGenerator()");
        }
        this.algorithm = CesecoreConfiguration.getCaSerialNumberAlgorithm();
        if (this.algorithm == null) {
            this.algorithm = "SHA1PRNG";
        }
        if ((noOctets > SERNO_MAX_LENGTH || noOctets < 0)) { // We allow 0 octets for testing
            throw new IllegalArgumentException("ca.serialnumberoctetsize must be between 0 and " + SERNO_MAX_LENGTH + " bytes for this serial number generator.");
        }
        this.noOctets = noOctets;        
        init();
        if (log.isTraceEnabled()) {
            log.trace("<SernoGenerator()");
        }
    }

    private void init() {
        // Init random number generator for random serial numbers. 
        // SecureRandom provides a cryptographically strong random number generator (CSPRNG).
        try {
            if (StringUtils.equalsIgnoreCase(algorithm, "BCSP800HYBRID")) {
                // Use a BC hybrid (FIPS/SP800 compliant) DRBG chain if ca.rngalgorithm is provided and it's defined as BCSP800Hybrid
                // create the seed material source - note can only be used to seed others. More info at HybridSecureRandom below.
                final SecureRandom source = new HybridSecureRandom();
                // create an actual random we can use
                random = new SP800SecureRandomBuilder(source, true)
                     .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Random"))
                     .buildHash(new SHA512Digest(), null, false);
                // Using FIPS libraries we could...
                // random = FipsDRBG.SHA256.fromEntropySource(entropySource, true).build(null, true);
                // and also register it as the default:
                // CryptoServicesRegistrar.setSecureRandom(random);
                log.info("Using FIPS/SP800 compliant Bouncy Castle Hybrid serialNumber RNG algorithm.");
            } else if (StringUtils.equalsIgnoreCase(algorithm, "defaultstrong")) {
                // If defaultstrong is specified and we use >=JDK8 try the getInstanceStrong to get a guaranteed strong random number generator.
                // Note that this may give you a generator that takes >30 seconds to create a single random number. 
                // On JDK8/Linux this gives you a NativePRNGBlocking, while SecureRandom.getInstance() gives a NativePRNG.
                random = SecureRandom.getInstanceStrong();
                log.info("Using SecureRandom.getInstanceStrong() with " + random.getAlgorithm() + " for serialNumber RNG algorithm.");
            } else if (StringUtils.equalsIgnoreCase(algorithm, "default")) {
                // We entered "default" so let's use a good default SecureRandom this should be good enough for just about everyone (on Linux at least)
                // On Linux the default Java implementation uses the (secure) /dev/(u)random, but on windows something else
                // On JDK8/Linux this gives you a NativePRNG, while SecureRandom.getInstanceStrong() gives a NativePRNGBlocking.
                random = new SecureRandom();
                log.info("Using default " + random.getAlgorithm() + " serialNumber RNG algorithm.");
            } else if (!StringUtils.isEmpty(algorithm)) {
                // Use a specified algorithm if ca.rngalgorithm is provided and it's not set to BCSP800Hybrid, default or defaultstrong
                random = SecureRandom.getInstance(algorithm);
                log.info("Using "+algorithm+" serialNumber RNG algorithm.");
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
        random.nextBytes(new byte[0]);
    }

    @Override
    public BigInteger getSerno() {
        // This is only for testing, if size is set to 0 we will generate random number
        // between 1 and 5, this will give collisions often...
        if (noOctets == 0) {
            final Random rand = new Random();
            return BigInteger.valueOf(rand.nextInt(4)+1); // value 1-5
        }
        while (true) {
             /*
                Note that initBitsOfEntropy are not left intact by the following subsequent filtering operations:
                - Values discarded to avoid encoding in less than noOctets (including zero value).
                - Serial numbers previously assigned to other certificates (filtered later, not here).
                So the real entropy provided for generated serial numbers is always less than initBitsOfEntropy.
                 */
            // initBitsOfEntropy is 1 less than octet size, because we always use positive integers, which in 
            // two complements representation always has the most significant bit 0, making 63 bits random
            int initBitsOfEntropy = noOctets * 8 - 1;
            // SecureRanom is thread safe. This will generate from (0 to 2^initBitsOfEntropy -1)
            final BigInteger serno = new BigInteger(initBitsOfEntropy, random);
            if (checkSernoValidity(serno)) {
                return serno;
            } else {
                String msg = intres.getLocalizedMessage("sernogenerator.discarding");
                log.info(msg);
            }
        }
    }

    /**
     * This validates that the argument is a non-zero number to be encoded (according to X.690, "8.3 Encoding of an
     * integer value") exactly in 'noOctets' bytes. For example, for an 8 bytes serial number it will validate that it
     * falls within the range 0080000000000000 - 7FFFFFFFFFFFFFFF (both inclusive).
     */
    protected boolean checkSernoValidity(final BigInteger serno) {
        return serno.compareTo(BigInteger.ZERO) != 0 && serno.bitLength() / 8 + 1 == noOctets;
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

    //Random using SecureRandomgetInstanceStrong() with
    //a FIPS compliant DRBG chain. Basically what happens is after initial
    //seed generation the base source uses a separate thread to gather
    //seed material and a core DRBG to satisfy any requests for seed material while
    //it waits. The only restriction on its use is that the HybridSecureRandom
    //can only be used as a source to other DRBGs which are then used
    //to generate randomness - if it's used for generating keys as well it will no
    //longer be FIPS compliant as the keys will effectively be exposing
    //samples of the random stream that is being used for seeding other DRBGs.

    /** Base seed material pool class */
    private static class HybridSecureRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final AtomicBoolean seedAvailable = new AtomicBoolean(false);
        private final AtomicInteger samples = new AtomicInteger(0);
        private final SecureRandom baseRandom;
        private final SP800SecureRandom drbg;

        HybridSecureRandom() {
            super(null, null); // stop getDefaultRNG() call
            try {
                // JDK 1.8 and later
                baseRandom = SecureRandom.getInstanceStrong();
            } catch (Exception e) {
                throw new IllegalStateException("unable to create baseRandom: " + e.getMessage(), e);
            }
            drbg = new SP800SecureRandomBuilder(new EntropySourceProvider() {
                public EntropySource get(final int bitsRequired) {
                    return new SignallingSeedMaterialSource(bitsRequired);
                }
            })
            .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Seed Material"))
            .buildHash(new SHA512Digest(), baseRandom.generateSeed(32), false); // 32 byte nonce
        }

        @Override
        public void setSeed(byte[] seed) {
            if (drbg != null) {
                drbg.setSeed(seed);
            }
        }

        @Override
        public void setSeed(long seed) {
            if (drbg != null) {
                drbg.setSeed(seed);
            }
        }

        @Override
        public byte[] generateSeed(int numBytes) {
            byte[] data = new byte[numBytes];
            // after 20 samples we'll start to check if there is new seed material.
            if (samples.getAndIncrement() > 20) {
                if (seedAvailable.getAndSet(false)) {
                    samples.set(0);
                    drbg.reseed((byte[])null);
                }
            }
            drbg.nextBytes(data);
            return data;
        }

        private class SignallingSeedMaterialSource implements EntropySource {
            private final int byteLength;
            private final AtomicReference<byte[]> seedmaterial = new AtomicReference<>();
            private final AtomicBoolean scheduled = new AtomicBoolean(false);

            SignallingSeedMaterialSource(int bitsRequired) {
                this.byteLength = (bitsRequired + 7) / 8;
            }

            @Override
            public boolean isPredictionResistant() {
                return true;
            }
            
            @Override
            public byte[] getEntropy() {
                byte[] seed = seedmaterial.getAndSet(null);

                if (seed == null || seed.length != byteLength) {
                    seed = baseRandom.generateSeed(byteLength);
                } else {
                    scheduled.set(false);
                }

                if (!scheduled.getAndSet(true)) {
                    new Thread(new SignallingSeedMaterialSource.EntropyGatherer(byteLength)).start();
                }

                return seed;
            }

            @Override
            public int entropySize() {
                return byteLength * 8;
            }

            private class EntropyGatherer implements Runnable {
                private final int numBytes;

                EntropyGatherer(int numBytes) {
                    this.numBytes = numBytes;
                }

                @Override
                public void run() {
                    seedmaterial.set(baseRandom.generateSeed(numBytes));
                    seedAvailable.set(true);
                }
            }
        }
    }

}
