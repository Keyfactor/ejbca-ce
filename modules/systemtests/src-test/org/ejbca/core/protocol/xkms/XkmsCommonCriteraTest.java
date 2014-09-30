/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.xkms;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 * This class represents a subset of tests required for common critera testing. 
 * 
 * @version $Id$
 *
 */
@Ignore
public class XkmsCommonCriteraTest {

    private XKMSKRSSTest test;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        XKMSKRSSTest.setupDatabaseAndInvoker();
        
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        XKMSKRSSTest.cleanDatabase();
    }
    
    @Before
    public void setUp() throws Exception {
        test = new XKMSKRSSTest();
        test.setUp();
    }
    
    @After
    public void tearDown() throws Exception {
    }
    
    @Test
    public void testCommonCriteria() throws Exception {
    
            test.test01SimpleRegistration();
            test.test17SimpleRevoke();
  
    }   
}
