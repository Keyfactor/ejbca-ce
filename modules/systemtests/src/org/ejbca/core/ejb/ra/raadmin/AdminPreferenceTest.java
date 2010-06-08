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
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.util.TestTools;

/**
 * Tests the admin preference entity bean.
 *
 * @version $Id$
 */
public class AdminPreferenceTest extends TestCase {
    private static Logger log = Logger.getLogger(AdminPreferenceTest.class);
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */
    private IRaAdminSessionRemote cacheAdmin;

    /** Handle to AdminSessionHome */
    private static IRaAdminSessionHome cacheHome;

    private static final String user = TestTools.genRandomUserName();

    /**
     * Creates a new AdminPreference object.
     *
     * @param name name
     */
    public AdminPreferenceTest(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
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

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.trace(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.trace("<getInitialContext");
        return ctx;
    }

    /**
     * tests adding an administrator preference
     *
     * @throws Exception error
     */
    public void test01AddAdminPreference() throws Exception {
        log.trace(">test01AddAdminPreference()");
        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);
        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        boolean ret = this.cacheAdmin.addAdminPreference(administrator, user, pref);
        assertTrue("Adminpref for "+user+" should not exist", ret);
        ret = this.cacheAdmin.addAdminPreference(administrator, user, pref);
        assertFalse("Adminpref for "+user+" should exist", ret);
        log.trace("<test01AddAdminPreference()");
    }

    /**
     * tests modifying an administrator preference
     *
     * @throws Exception error
     */
    public void test02ModifyAdminPreference() throws Exception {
        log.trace(">test02ModifyAdminPreference()");
        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);
        AdminPreference pref = this.cacheAdmin.getAdminPreference(administrator, user);
        assertTrue("Error Retreiving Administrator Preference.", pref.getPreferedLanguage() == 1);
        assertTrue("Error Retreiving Administrator Preference.", pref.getTheme().equals("TEST"));
        pref.setPreferedLanguage(2);
        boolean ret = this.cacheAdmin.changeAdminPreference(administrator, user, pref);
        assertTrue("Adminpref for "+user+" should exist", ret);
        pref = this.cacheAdmin.getAdminPreference(administrator, user);
        assertEquals(pref.getPreferedLanguage(), 2);
        String newuser = TestTools.genRandomUserName();
        ret = this.cacheAdmin.changeAdminPreference(administrator, newuser, pref);
        assertFalse("Adminpref for "+newuser+" should not exist", ret);
        log.trace("<test02ModifyAdminPreference()");
    }

}
