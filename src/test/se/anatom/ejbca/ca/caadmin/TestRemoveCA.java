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

package se.anatom.ejbca.ca.caadmin;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.log.Admin;

/**
 * Tests and removes the ca data entity bean.
 *
 * @version $Id: TestRemoveCA.java,v 1.1 2004-06-10 16:17:43 sbailliez Exp $
 */
public class TestRemoveCA extends TestCase {
    private static Logger log = Logger.getLogger(TestCAs.class);

    private ICAAdminSessionRemote cacheAdmin;


    private static ICAAdminSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCAs object.
     *
     * @param name name
     */
    public TestRemoveCA(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CAAdminSession");
                cacheHome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
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
     * removes CA
     *
     * @throws Exception error
     */
    public void test01removeCA() throws Exception {
        log.debug(">test01removeCA()");
        boolean ret = false;
        try {
            cacheAdmin.removeCA(admin, "CN=TEST".hashCode());
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing CA failed", ret);

        log.debug("<test01removeCA()");
    }


}
