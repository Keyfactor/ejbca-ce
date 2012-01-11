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
package org.ejbca.core.protocol.ws;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Represents a subset of WS tests to quickly get an estimate of CC compliance.
 * 
 * @version $Id$
 *
 */
@Ignore
public class EjbcaWsCommonCriteriaTest {

    private EjbcaWSTest test;
    
    @BeforeClass
    public static void beforeClass() {
        EjbcaWSTest.beforeClass();
    }
    
    @Before
    public void setUp() throws Exception {
        test = new EjbcaWSTest();
        test.test00SetupAccessRights();
        test.setUpAdmin();
    }
    
    @After
    public void tearDown() throws Exception {
        test.test99cleanUpAdmins();
        test.tearDown();
    }
    
    @Test
    public void testCertificateLifeCycle() {
        //Complete life cycle is done as a part of setup and cleanup
    }
    
    @Test
    public void testCrlIssuance() throws Exception {
        test.test25GreateCRL();
    }
    
    @Test
    public void testEndEndEntityManagement() {
        //Complete life cycle is done as a part of setup and cleanup
    }
    
    @Test
    public void testKeyRecovery() throws Exception {
        test.test20KeyRecoverNewest();
    }
}
