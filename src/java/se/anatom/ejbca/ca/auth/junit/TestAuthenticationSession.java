package se.anatom.ejbca.ca.auth.junit;

import java.util.Date;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionHome;
import se.anatom.ejbca.ca.auth.IAuthenticationSessionRemote;
import se.anatom.ejbca.ca.auth.UserAuthData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserDataHome;
import se.anatom.ejbca.ra.UserDataPK;
import se.anatom.ejbca.ra.UserDataRemote;

/**
 * Tests authentication session used by signer.
 *
 * @version $Id: TestAuthenticationSession.java,v 1.17 2003-11-02 10:15:21 anatom Exp $
 */
public class TestAuthenticationSession extends TestCase {
    private static Logger log = Logger.getLogger(TestAuthenticationSession.class);
    
    private static Context ctx;
    private static IAuthenticationSessionRemote remote;
    private static IUserAdminSessionRemote usersession;
    private static String username;
    private static String pwd;
    private static int caid=1;
    private static Admin admin = null;

    /**
     * Creates a new TestAuthenticationSession object.
     *
     * @param name name
     */
    public TestAuthenticationSession(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        ctx = getInitialContext();
        Object obj = ctx.lookup("AuthenticationSession");
        IAuthenticationSessionHome home = (IAuthenticationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IAuthenticationSessionHome.class);
        remote = home.create();
        obj = ctx.lookup("UserAdminSession");        
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
        Random rand = new Random(new Date().getTime()+4711);
        String name = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            name += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return name;
    } // genRandomUserName

    private String genRandomPwd() throws Exception {
        // Gen random pwd
        Random rand = new Random(new Date().getTime()+4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd


    /**
     * tests creation of new users
     *
     * @throws Exception error
     */
    public void test01CreateNewUser() throws Exception {
        log.debug(">test01CreateNewUser()");

        // Make user that we know later...
        username = genRandomUserName();
        pwd = genRandomPwd();
        String email = username+"@anatom.se";
        usersession.addUser(admin,username,pwd,"C=SE, O=AnaTom, CN="+username,"rfc822name="+email,email,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_P12,0,caid);
        log.debug("created user: "+username+", "+pwd+", C=SE, O=AnaTom, CN="+username);
        
        log.debug("<test01CreateNewUser()");
    }

    /**
     * Tests authentiction of users
     *
     * @throws Exception error
     */
    public void test02AuthenticateUser() throws Exception {
        log.debug(">test02AuthenticateUser()");
        // user that we know exists...
        log.debug("Username:"+username+"\npwd:"+pwd);
        UserAuthData data = remote.authenticateUser(admin, username, pwd);

        log.debug("DN: "+data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username) != -1);

        log.debug("Email: "+data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username+"@anatom.se"));

        log.debug("Type: "+data.getType());
        assertTrue("Type is wrong", data.getType() == SecConst.USER_ENDUSER);
        log.debug("<test02AuthenticateUser()");
    }

    /**
     * Tests filed authentication
     *
     * @throws Exception error
     */
    public void test03FailAuthenticateUser() throws Exception {
        log.debug(">test03FailAuthenticateUser()");

        // user that we know exists...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        UserDataPK pk = new UserDataPK(username);
        UserDataRemote data = userhome.findByPrimaryKey(pk);
        // Set status to GENERATED so authentication will fail
        data.setStatus(UserDataRemote.STATUS_GENERATED);
        boolean authfailed = false;
        try {
            UserAuthData auth = remote.authenticateUser(admin, username, pwd);
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.debug("<test03FailAuthenticateUser()");
    }

    /**
     * Tests more failed authentication
     *
     * @throws Exception error
     */
    public void test04FailAuthenticateUser() throws Exception {
        log.debug(">test04FailAuthenticateUser()");
        // user that we know exists... but we issue wrong password
        boolean authfailed = false;
        try {
            UserAuthData auth = remote.authenticateUser(admin, username, "abc123");
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.debug("<test04FailAuthenticateUser()");
    }
}
