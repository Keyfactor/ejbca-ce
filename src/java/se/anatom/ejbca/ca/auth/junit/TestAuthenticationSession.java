package se.anatom.ejbca.ca.auth.junit;

import java.rmi.RemoteException;
import java.util.*;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import junit.framework.*;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.auth.*;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.*;


/**
 * Tests authentication session used by signer.
 *
 * @version $Id: TestAuthenticationSession.java,v 1.13 2003-07-24 08:43:30 anatom Exp $
 */
public class TestAuthenticationSession extends TestCase {
    private static Logger log = Logger.getLogger(TestAuthenticationSession.class);
    private static Context ctx;
    private static IAuthenticationSessionHome home;
    private static IAuthenticationSessionRemote remote;
    private static String username;
    private static String pwd;

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
        home = (IAuthenticationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
                IAuthenticationSessionHome.class);
        remote = home.create();
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
    }

    // genRandomUserName
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
    }

    // genRandomPwd

    /**
     * tests creation of new users
     *
     * @throws Exception error
     */
    public void test01CreateNewUser() throws Exception {
        log.debug(">test01CreateNewUser()");

        // Make user that we know later...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                UserDataHome.class);
        username = genRandomUserName();
        pwd = genRandomPwd();

        try {
            UserDataRemote createdata = userhome.create(username, pwd,
                    "C=SE, O=AnaTom, CN=" + username);
            assertNotNull("Failed to create user " + username, createdata);
            createdata.setType(SecConst.USER_ENDUSER);
            createdata.setSubjectEmail(username + "@anatom.se");
            log.debug("created user: " + username + ", " + pwd + ", C=SE, O=AnaTom, CN=" +
                username);
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                assertNotNull("Cannot create random user " + username, null);
            }
        } catch (DuplicateKeyException dke) {
            assertNotNull("Cannot create random user " + username, null);
        }

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
        UserAuthData data = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER), username,
                pwd);

        log.debug("DN: " + data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username) != -1);

        log.debug("Email: " + data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username + "@anatom.se"));

        log.debug("Type: " + data.getType());
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
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                UserDataHome.class);
        UserDataPK pk = new UserDataPK(username);
        UserDataRemote data = userhome.findByPrimaryKey(pk);

        // Set status to GENERATED so authentication will fail
        data.setStatus(UserDataRemote.STATUS_GENERATED);

        boolean authfailed = false;

        try {
            UserAuthData auth = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER),
                    username, pwd);
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
            UserAuthData auth = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER),
                    username, "abc123");
        } catch (Exception e) {
            authfailed = true;
        }

        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        log.debug("<test04FailAuthenticateUser()");
    }
}
