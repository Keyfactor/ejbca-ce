/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 *
 */
public class KeyPairWrapperTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
        
    @Test
    public void testGetKeyPair() throws InvalidAlgorithmParameterException {
        KeyPair testKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        KeyPairWrapper testWrapper = new KeyPairWrapper(testKeys);
        assertEquals("Decoded public key was not identical to encoded.", testKeys.getPublic(), testWrapper.getKeyPair().getPublic());
        assertEquals("Decoded private key was not identical to encoded.", testKeys.getPrivate(), testWrapper.getKeyPair().getPrivate());
    }
    
}
