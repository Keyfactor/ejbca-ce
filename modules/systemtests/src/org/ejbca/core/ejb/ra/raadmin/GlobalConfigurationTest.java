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

import javax.ejb.EJB;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Tests the global configuration entity bean.
 *
 * @version $Id$
 */
public class GlobalConfigurationTest extends TestCase {
    private static Logger log = Logger.getLogger(GlobalConfigurationTest.class);

    private static GlobalConfiguration original = null;
    
    @EJB
    private RaAdminSessionRemote raAdminSession;


    /**
     * Creates a new TestGlobalConfiguration object.
     *
     * @param name name
     */
    public GlobalConfigurationTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {

    }

    public void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.trace(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.trace("<getInitialContext");
        return ctx;
    }


    /**
     * tests adding a global configuration
     *
     * @throws Exception error
     */
    public void test01AddGlobalConfiguration() throws Exception {
        log.trace(">test01AddGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        // First save the original
        original = this.raAdminSession.loadGlobalConfiguration(administrator);

        GlobalConfiguration conf = new GlobalConfiguration();
        conf.setEjbcaTitle("TESTTITLE");
        this.raAdminSession.saveGlobalConfiguration(administrator, conf);

        log.trace("<test01AddGlobalConfiguration()");
    }

    /**
     * tests modifying an global configuration
     *
     * @throws Exception error
     */
    public void test02ModifyGlobalConfiguration() throws Exception {
        log.trace(">test01ModifyGlobalConfiguration()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        GlobalConfiguration conf = this.raAdminSession.loadGlobalConfiguration(administrator);
        assertTrue("Error Retreiving Global Configuration.", conf.getEjbcaTitle().equals("TESTTITLE"));

        conf.setEjbcaTitle("TESTTITLE2");
        this.raAdminSession.saveGlobalConfiguration(administrator, conf);

        // Replace with original
        this.raAdminSession.saveGlobalConfiguration(administrator, original);

        log.trace("<test01ModifyGlobalConfiguration()");
    }


}
