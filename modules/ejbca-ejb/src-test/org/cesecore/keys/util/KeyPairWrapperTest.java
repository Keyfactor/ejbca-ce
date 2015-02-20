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
package org.cesecore.keys.util;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class KeyPairWrapperTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
        
    @Test
    public void testGetKeyPair() throws InvalidAlgorithmParameterException, InvalidKeySpecException {
        KeyPair testKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        KeyPairWrapper testWrapper = new KeyPairWrapper(testKeys);
        assertEquals("Decoded public key was not identical to encoded.", testKeys.getPublic(), testWrapper.getKeyPair().getPublic());
        assertEquals("Decoded private key was not identical to encoded.", testKeys.getPrivate(), testWrapper.getKeyPair().getPrivate());
    }
    
}
