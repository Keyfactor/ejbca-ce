/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

/**
 * Test class fot RSA key validator functional methods, see {@link RsaKeyValidator}.
 * 
 * @version $Id$
 */
package org.cesecore.keys.validation;

import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests ECC key validator functions.
 * 
 * @version $Id$
 */
public class EccKeyValidatorTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(EccKeyValidatorTest.class);

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        // NOOP
        log.trace("<tearDown()");
    }

    @Test
    public void test01PublicKeyPartialEcValidation() throws Exception {
        log.trace(">test01PublicKeyPartialEcValidation()");
        //fail("ECA-4219 Not implemented: ECC partial validation.");
        log.trace("<test01PublicKeyPartialEcValidation()");
    }

    @Test
    public void test02PublicKeyFullEcValidation() throws Exception {
        log.trace(">test02PublicKeyFullEcValidation()");
        //fail("ECA-4219 Not implemented: ECC full validation.");
        log.trace("<test02PublicKeyFullEcValidation()");
    }
}
