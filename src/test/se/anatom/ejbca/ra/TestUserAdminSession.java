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

package se.anatom.ejbca.ra;

import java.util.Date;
import java.util.Random;
import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.exception.NotFoundException;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id: TestUserAdminSession.java,v 1.2 2005-02-11 13:12:16 anatom Exp $
 */
public class TestUserAdminSession extends TestCase {

    private static Logger log = Logger.getLogger(TestUserAdminSession.class);
    private static Context ctx;
    private static IUserAdminSessionRemote usersession;
    private static String username;
    private static String pwd;
    private static int caid;
    private static Admin admin = null;

    /**
     * Creates a new TestUserData object.
     *
     * @param name DOCUMENT ME!
     */
    public TestUserAdminSession(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");
        ctx = getInitialContext();
        caid = "CN=TEST".hashCode();
        Object obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();
        admin = new Admin(Admin.TYPE_INTERNALUSER);

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

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";

        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }

        log.debug("Generated random pwd: password=" + password);

        return password;
    } // genRandomPwd


    /**
     * tests creation of new user and duplicate user
     *
     * @throws Exception error
     */
    public void test01AddUser() throws Exception {
        log.debug(">test01AddUser()");

        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
        String email = username + "@anatom.se";
        usersession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" + username);
        // Add the same user again
        boolean userexists = false;
        try {
            usersession.addUser(admin, username, pwd, "C=SE, O=AnaTom, CN=" + username, "rfc822name=" + email, email, false, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.USER_ENDUSER, SecConst.TOKEN_SOFT_P12, 0, caid);
        } catch (DuplicateKeyException e) {
            // This is what we want
            userexists = true;
        }
        assertTrue("User already exist does not throw DuplicateKeyException", userexists);

        log.debug("<test01AddUser()");
    }

    /**
     * tests deletion of user, and user that does not exist
     *
     * @throws Exception error
     */
    public void test01DeleteUser() throws Exception {
        log.debug(">test01DeleteUser()");

        usersession.deleteUser(admin, username);
        log.debug("deleted user: " + username);
        // Delete the the same user again
        boolean removed = false;
        try {
            usersession.deleteUser(admin, username);
        } catch (NotFoundException e) {
            removed = true;
        }
        assertTrue("User does not exist does not throw NotFoundException", removed);

        log.debug("<test01DeleteUser()");
    }
}
