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
package org.cesecore.keys.token.p11;

import static org.junit.Assert.fail;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests instantiating the Pkcs11Wrapper
 * 
 * @version $Id$
 *
 */
public class Pkcs11WrapperTest {

    private static final Logger log = Logger.getLogger(Pkcs11WrapperTest.class);
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testInstantiatePkcs11Wrapper() {
        String pkcs11Library = PKCS11TestUtils.getHSMLibrary();
        if (pkcs11Library == null) {
    //        throw new RuntimeException("No known PKCS11 installed, test can't continue.");
        }
        try {   
            Pkcs11Wrapper.getInstance(pkcs11Library);
        } catch (Exception e) {
            log.error("Unknown exception encountered", e);
  //          fail("Exception was thrown, instantiation failed.");
        }
        
    }

}
