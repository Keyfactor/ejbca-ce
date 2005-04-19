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

package se.anatom.ejbca.ra.raadmin;

import java.util.Date;
import java.util.Random;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.log.Admin;

/**
 * Tests the admin preference entity bean.
 *
 * @version $Id: TestAdminPreference.java,v 1.2 2005-04-19 12:15:52 anatom Exp $
 */
public class TestAdminPreference extends TestCase {
    private static Logger log = Logger.getLogger(TestAdminPreference.class);
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */
    private IRaAdminSessionRemote cacheAdmin;

    /** Handle to AdminSessionHome */
    private static IRaAdminSessionHome cacheHome;

    private static final String user = genRandomUserName();


    /**
     * Creates a new AdminPreference object.
     *
     * @param name name
     */
    public TestAdminPreference(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("RaAdminSession");
                cacheHome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);

            }

            cacheAdmin = cacheHome.create();
        }


        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");

        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }


    /**
     * tests adding an administrator preference
     *
     * @throws Exception error
     */
    public void test01AddAdminPreference() throws Exception {
        log.debug(">test01AddAdminPreference()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        AdminPreference pref = new AdminPreference();
        pref.setPreferedLanguage(1);
        pref.setTheme("TEST");
        this.cacheAdmin.addAdminPreference(administrator, "1234", pref);

        log.debug("<test01AddAdminPreference()");
    }

    /**
     * tests modifying an administrator preference
     *
     * @throws Exception error
     */
    public void test02ModifyAdminPreference() throws Exception {
        log.debug(">test01ModifyAdminPreference()");

        Admin administrator = new Admin(Admin.TYPE_INTERNALUSER);

        AdminPreference pref = this.cacheAdmin.getAdminPreference(administrator, "1234");
        assertTrue("Error Retreiving Administrator Preference.", pref.getPreferedLanguage() == 1);
        assertTrue("Error Retreiving Administrator Preference.", pref.getTheme().equals("TEST"));

        pref.setPreferedLanguage(2);

        this.cacheAdmin.changeAdminPreference(administrator, user, pref);

        log.debug("<test01ModifyAdminPreference()");
    }

    private static String genRandomUserName() {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        //log.debug("Generated random username: username =" + username);

        return username;
    } // genRandomUserName

}
