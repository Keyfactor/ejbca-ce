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
package org.cesecore.keys.util;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Test of the class SignWithWorkingAlgorithm.
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class SignWithWorkingAlgorithmTest {
    /**
     * This list starts on purpose with long hashing algorithms that will not
     * be handled by a 512bit key. Since first test is the 512 bit key some
     * algorithms must be tried before finding the working one.
     * If the test should have started with 2048 bit key then the signing with
     * 512 should have failed since the chosen algorithm had to long hash for
     * this key.
     * So in real life the list should start with the short algorithms.
     */
    public static final List<String> SIG_ALGS_RSA = Collections.unmodifiableList(Arrays.asList(
            "someBogusName",
            "SHA512withRSAandMGF1",
            AlgorithmConstants.SIGALG_SHA512_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1,
            AlgorithmConstants.SIGALG_SHA256_WITH_RSA,
            AlgorithmConstants.SIGALG_SHA1_WITH_RSA
    ));
    private class SignOperation implements SignWithWorkingAlgorithm.Operation<GeneralSecurityException> {

        public SignOperation( final KeyPair kp ) {
            this.keyPair = kp;
        }
        final private byte bvOriginal[] = "Här är orginalet!".getBytes();
        final private KeyPair keyPair;
        private byte bvSignature[];
        private String usedAlgorithm;
        private int nrOfCalls = 0;
        @Override
        public void doIt(final String algorithm, final Provider provider) throws GeneralSecurityException {
            this.nrOfCalls++;
            final Signature signature = Signature.getInstance(algorithm, provider);
            signature.initSign(this.keyPair.getPrivate());
            signature.update(this.bvOriginal);
            this.bvSignature = signature.sign();
            this.usedAlgorithm = algorithm;
        }
        public boolean verifySignature() throws GeneralSecurityException {
            final Signature signature = Signature.getInstance(this.usedAlgorithm, BouncyCastleProvider.PROVIDER_NAME);
            signature.initVerify(this.keyPair.getPublic());
            signature.update(this.bvOriginal);
            return signature.verify(this.bvSignature);
        }
        public String getUsedAlgorithm() {
            return this.usedAlgorithm;
        }
        public int getNrOfCalls() {
            return this.nrOfCalls;
        }
    }
    private static KeyPair generateKeyPair( final int size ) throws NoSuchAlgorithmException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(size);
        return kpg.generateKeyPair();
    }
    /**
     * Register BC provider before starting the test.
     */
    @BeforeClass
    public static void before() {
        if ( Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)!=null ) {
            return;
        }
        Security.addProvider(new BouncyCastleProvider());
    }
    /**
     * First time for BC provider. Check that 5 tries are made until
     * SIGALG_SHA1_WITH_RSA_AND_MGF1 that is working is found. The key is too
     * short for first algorithms.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n1BC512() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(512));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, BouncyCastleProvider.PROVIDER_NAME, operation) );
        assertTrue(operation.verifySignature());
        assertEquals(5, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, operation.getUsedAlgorithm());
    }
    /**
     * Second time the right key is picked directly.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n2BC2048() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(2048));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, BouncyCastleProvider.PROVIDER_NAME, operation) );
        assertTrue(operation.verifySignature());
        assertEquals(1, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, operation.getUsedAlgorithm());
    }
    /**
     * The provider SunRsaSign is not supporting MGF1 so we have to try one more time.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n3SunRsaSign512() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(512));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, "SunRsaSign", operation) );
        assertTrue(operation.verifySignature());
        assertEquals(6, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, operation.getUsedAlgorithm());
    }
    /**
     * Second time the right key is picked directly.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n4SunRsaSign2048() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(2048));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, "SunRsaSign", operation) );
        assertTrue(operation.verifySignature());
        assertEquals(1, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, operation.getUsedAlgorithm());
    }
    /**
     * Just checking that right algorithm is stilled picked for the BC provider.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n5BC1024() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(1024));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, BouncyCastleProvider.PROVIDER_NAME, operation) );
        assertTrue(operation.verifySignature());
        assertEquals(1, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA1_WITH_RSA_AND_MGF1, operation.getUsedAlgorithm());
    }
    /**
     * Just checking that right algorithm is stilled picked for the SunRsaSign provider.
     * @throws NoSuchProviderException
     * @throws GeneralSecurityException
     */
    @Test
    public void n6SunRsaSign1024() throws NoSuchProviderException, GeneralSecurityException {
        final SignOperation operation = new SignOperation(generateKeyPair(1024));
        assertTrue( SignWithWorkingAlgorithm.doIt(SIG_ALGS_RSA, "SunRsaSign", operation) );
        assertTrue(operation.verifySignature());
        assertEquals(1, operation.getNrOfCalls());
        assertEquals(AlgorithmConstants.SIGALG_SHA256_WITH_RSA, operation.getUsedAlgorithm());
    }
}
