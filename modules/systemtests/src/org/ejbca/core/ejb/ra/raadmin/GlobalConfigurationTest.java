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

    private IRaAdminSessionRemote cacheAdmin;

    private static IRaAdminSessionHome cacheHome;

    private static GlobalConfiguration original = null;


    /**
     * Creates a new TestGlobalConfiguration object.
     *
     * @param name name
     */
    public GlobalConfigurationTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("RaAdminSession");
                cacheHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);

            }
            cacheAdmin = cacheHome.create();
        }
        log.trace("<setUp()");
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
        original = this.cacheAdmin.loadGlobalConfiguration(administrator);

        GlobalConfiguration conf = new GlobalConfiguration();
        conf.setEjbcaTitle("TESTTITLE");
        this.cacheAdmin.saveGlobalConfiguration(administrator, conf);

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

        GlobalConfiguration conf = this.cacheAdmin.loadGlobalConfiguration(administrator);
        assertTrue("Error Retreiving Global Configuration.", conf.getEjbcaTitle().equals("TESTTITLE"));

        conf.setEjbcaTitle("TESTTITLE2");
        this.cacheAdmin.saveGlobalConfiguration(administrator, conf);

        // Replace with original
        this.cacheAdmin.saveGlobalConfiguration(administrator, original);

        log.trace("<test01ModifyGlobalConfiguration()");
    }


}
