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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class PublicKeyWrapperTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void testGetPublicKey() throws InvalidAlgorithmParameterException, InvalidKeySpecException {
        PublicKey testKey = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA).getPublic();
        PublicKeyWrapper testWrapper = new PublicKeyWrapper(testKey);
        assertEquals("Decoded PublicKey was not identical to encoded.", testKey, testWrapper.getPublicKey());
    }
    
}
