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

package se.anatom.ejbca.batch;

import java.io.File;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;

/** Tests the batch making of soft cards.
 *
 * @version $Id: TestBatchMakeP12.java,v 1.2 2005-02-11 13:12:14 anatom Exp $
 */

public class TestBatchMakeP12 extends TestCase {
    private static Logger log = Logger.getLogger(TestBatchMakeP12.class);
    private static Context ctx;
    private static IUserAdminSessionHome home;
    private static int caid;
    private static Admin admin;

    /**
     * Creates a new TestBatchMakeP12 object.
     *
     * @param name name
     */
    public TestBatchMakeP12(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
        ctx = getInitialContext();
        Object obj = ctx.lookup("UserAdminSession");
        home = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);

        obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer) iter.next()).intValue();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
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

    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";

        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }

        log.debug("Generated random username: username =" + username);

        return username;
    } // genRandomUserName

    /**
     * test creation of new user
     *
     * @throws Exception error
     */
    public void test01CreateNewUsers() throws Exception {
        log.debug(">test01CreateNewUser()");
        IUserAdminSessionRemote data1 = null;
        String username = genRandomUserName();

        data1 = home.create();

        Object o = null;
        try {
            data1.addUser(admin, username, "foo123", "C=SE, O=AnaTom, CN=" + username, "", username + "@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
            data1.setClearTextPassword(admin, username, "foo123");
            o = new String("");
        } catch (Exception e) {
            assertNotNull("Failed to create user " + username, o);
        }

        log.debug("created " + username + ", pwd=foo123");

        String username1 = genRandomUserName();
        o = null;
        try {
            data1.addUser(admin, username1, "foo123", "C=SE, O=AnaTom, CN=" + username1, "", username1 + "@anatom.se", false,
                    SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER,
                    SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
            data1.setClearTextPassword(admin, username1, "foo123");
            o = new String("");
        } catch (Exception e) {
            assertNotNull("Failed to create user " + username1, o);
        }
        log.debug("created " + username1 + ", pwd=foo123");
        log.debug("<test01CreateNewUsers()");
    }

    /**
     * Tests creation of P12 file
     *
     * @throws Exception error
     */
    public void test02MakeP12() throws Exception {
        log.debug(">test02MakeP12()");

        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");

        //System.out.println("tempdir="+tmpfile.getParent());
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        log.debug("<test02MakeP12()");
    }
}
