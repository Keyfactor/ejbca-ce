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

import java.util.Calendar;
import java.util.Date;
import java.util.Random;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.CertTools;

/**
 * Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id: TestAddLotsofUsers.java,v 1.1 2004-06-10 16:17:44 sbailliez Exp $
 */
public class TestAddLotsofUsers extends TestCase {
    private static Logger log = Logger.getLogger(TestAddLotsofUsers.class);
    /**
     * UserAdminSession handle, not static since different object should go to different session
     * beans concurrently
     */
    private IUserAdminSessionRemote cacheAdmin;

    /** Handle to AdminSessionHome */
    private static IUserAdminSessionHome cacheHome;

    //private static UserDataHome home;
    private static String baseUsername;
    private static String pwd;
    private static String pwd1;
    private static int userNo = 0;
    private static int caid;

    /**
     * Creates a new TestAddLotsofUsers object.
     *
     * @param name name
     */
    public TestAddLotsofUsers(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");
        //Object obj = ctx.lookup("UserData");
        //home = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj, UserDataHome.class);
        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("UserAdminSession");
                cacheHome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
                caid = "CN=TEST".hashCode();

            }

            cacheAdmin = cacheHome.create();
        }

        Calendar cal = Calendar.getInstance();
        baseUsername = "lotsausers" + cal.get(Calendar.SECOND) + "-";


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

    private String genUserName() throws Exception {
        // Gen new user
        userNo++;

        return baseUsername + userNo;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";

        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }

        //log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd


    /**
     * tests creating 2000 users
     *
     * @throws Exception error
     */
    public void test01Create2000Users() throws Exception {
        log.debug(">test01Create2000Users()");

        //UserDataRemote data1=null;
        Admin administrator = new Admin(Admin.TYPE_RACOMMANDLINE_USER);

        for (int i = 0; i < 2000; i++) {
            String username = genUserName();
            pwd = genRandomPwd();

            /*
            data1 = home.create(username, pwd, "C=SE, O=AnaTom, CN="+username);
            assertNotNull("Error creating", data1);
            */
            int type = SecConst.USER_ENDUSER;
            int token = SecConst.TOKEN_SOFT_P12;
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            boolean error = false;
            boolean usehardtokenissuer = false;
            String dn = "C=SE, O=AnaTom, CN=" + username;
            String subjectaltname = "rfc822Name=" + username + "@foo.se";
            String email = username + "@foo.se";
            if (cacheAdmin.findUser(administrator, username) != null) {
                ;
                System.out.println("Error : User already exists in the database.");
                error = true;
            }
            cacheAdmin.addUser(administrator, username, pwd, CertTools.stringToBCDNString(dn), subjectaltname, email, false, profileid, certificatetypeid,
                    type, token, hardtokenissuerid, caid);
            cacheAdmin.setClearTextPassword(administrator, username, pwd);
            if (i % 100 == 0) {
                log.debug("Created " + i + " users...");
            }
        }
        log.debug("Created 2000 users!");
        log.debug("<test01Create2000Users()");
    }
}
