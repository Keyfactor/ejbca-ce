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

package org.ejbca.core.ejb.ra.raadmin;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the global configuration entity bean.
 *
 * @version $Id$
 */
public class GlobalConfigurationTest extends TestCase {
    private static Logger log = Logger.getLogger(GlobalConfigurationTest.class);
    
    private RaAdminSessionRemote raAdminSession = InterfaceCache.getRAAdminSession();

    private Admin administrator;
    private GlobalConfiguration original;
    
    /**
     * Creates a new TestGlobalConfiguration object.
     *
     * @param name name
     */
    public GlobalConfigurationTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        administrator = new Admin(Admin.TYPE_INTERNALUSER);
        
        // First save the original
        original = this.raAdminSession.loadGlobalConfiguration(administrator);
    }

    public void tearDown() throws Exception {
        raAdminSession.saveGlobalConfiguration(administrator, original);
        administrator = null;
    }

    /**
     * tests adding a global configuration
     *
     * @throws Exception error
     */
    public void testAddGlobalConfiguration() throws Exception {
        GlobalConfiguration conf = new GlobalConfiguration();
        conf.setEjbcaTitle("TESTTITLE");
        raAdminSession.saveGlobalConfiguration(administrator, conf);
        
        assertTrue("Global configuration was not correctly set.", raAdminSession.loadGlobalConfiguration(administrator).getEjbcaTitle().equals("TESTTITLE"));
        
    }

    /**
     * tests modifying an global configuration
     *
     * @throws Exception error
     */
    public void testModifyGlobalConfiguration() throws Exception {
        GlobalConfiguration conf = new GlobalConfiguration();
        
        conf.setEjbcaTitle("TESTTITLE");
        raAdminSession.saveGlobalConfiguration(administrator, conf);
        assertTrue("Global configuration was not correctly set.", raAdminSession.loadGlobalConfiguration(administrator).getEjbcaTitle().equals("TESTTITLE"));
        
        conf.setEjbcaTitle("TESTTITLE2");
        raAdminSession.saveGlobalConfiguration(administrator, conf);
        assertTrue("Global Configuration was not correctly modified.", raAdminSession.loadGlobalConfiguration(administrator).getEjbcaTitle().equals("TESTTITLE2"));

        // Replace with original
        raAdminSession.saveGlobalConfiguration(administrator, original);
    }


}
