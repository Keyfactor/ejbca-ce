package se.anatom.ejbca.ra.junit;

import java.util.*;

import javax.naming.Context;
import javax.naming.NamingException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.Logger;
import junit.framework.*;

/** Tests the UserData entity bean and some parts of UserAdminSession.
 *
 * @version $Id: TestAddLotsofUsers.java,v 1.1 2003-03-04 11:02:23 anatom Exp $
 */
public class TestAddLotsofUsers extends TestCase {

    private static Logger log = Logger.getLogger(TestUserData.class);
    private static Context ctx;
    private static UserDataHome home;
    private static String username;
    private static String username1;
    private static String pwd;
    private static String pwd1;
    private static int userNo=0;

    public TestAddLotsofUsers(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("UserData");
        home = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj, UserDataHome.class);
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
        // Gen random user
        String username = "lotsausers";
        userNo++;
        username += userNo;
        //log.debug("Generated random username: username =" + username);
        return username;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime()+4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }

        //log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd



    public void test01Create2000Users() throws Exception {
        log.debug(">test01Create2000Users()");
        UserDataRemote data1=null;
        for (int i=0;i<2000;i++) {
            username = genUserName();
            pwd = genRandomPwd();
            data1 = home.create(username, pwd, "C=SE, O=AnaTom, CN="+username);
            assertNotNull("Error creating", data1);
            if (i%500 == 0) {
                log.debug("Created "+i+" users...");
            }
        }
        log.debug("Created 2000 users!");
        log.debug("<test01Create2000Users()");
    }

}

