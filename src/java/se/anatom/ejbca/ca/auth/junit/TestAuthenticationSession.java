package se.anatom.ejbca.ca.auth.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;

import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import javax.ejb.DuplicateKeyException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.auth.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.*;
import junit.framework.*;

/** Tests authentication session used by signer.
 *
 * @version $Id: TestAuthenticationSession.java,v 1.10 2003-01-12 17:16:33 anatom Exp $
 */
public class TestAuthenticationSession extends TestCase {
    static Category cat = Category.getInstance( TestAuthenticationSession.class.getName() );
    private static Context ctx;
    private static IAuthenticationSessionHome home;
    private static IAuthenticationSessionRemote remote;
    private static String username;
    private static String pwd;

    public TestAuthenticationSession(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("AuthenticationSession");
        home = (IAuthenticationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IAuthenticationSessionHome.class);
        remote = home.create();
        cat.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        cat.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        cat.debug("<getInitialContext");
        return ctx;
    }
    private String genRandomUserName() throws Exception {
        // Gen random user
        Random rand = new Random(new Date().getTime()+4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        cat.debug("Generated random username: username =" + username);
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

        cat.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd

    public void test01CreateNewUser() throws Exception {
        cat.debug(">test01CreateNewUser()");

        // Make user that we know later...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        username = genRandomUserName();
        pwd = genRandomPwd();
        try {
            UserDataRemote createdata = userhome.create(username, pwd, "C=SE, O=AnaTom, CN="+username);
            assertNotNull("Failed to create user "+username, createdata);
            createdata.setType(SecConst.USER_ENDUSER);
            createdata.setSubjectEmail(username+"@anatom.se");
            cat.debug("created user: "+username+", "+pwd+", C=SE, O=AnaTom, CN="+username);
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                assertNotNull("Cannot create random user "+username, null);
            }
        } catch (DuplicateKeyException dke) {
            assertNotNull("Cannot create random user "+username, null);
        }
        cat.debug("<test01CreateNewUser()");
    }

    public void test02AuthenticateUser() throws Exception {
        cat.debug(">test02AuthenticateUser()");
        // user that we know exists...
        UserAuthData data = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER), username, pwd);

        cat.debug("DN: "+data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf(username) != -1);

        cat.debug("Email: "+data.getEmail());
        assertNotNull("Email should not be null", data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals(username+"@anatom.se"));

        cat.debug("Type: "+data.getType());
        assertTrue("Type is wrong", data.getType() == SecConst.USER_ENDUSER);
        cat.debug("<test02AuthenticateUser()");
    }

    public void test03FailAuthenticateUser() throws Exception {
        cat.debug(">test03FailAuthenticateUser()");
        // user that we know exists...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        UserDataPK pk = new UserDataPK(username);
        UserDataRemote data = userhome.findByPrimaryKey(pk);
        // Set status to GENERATED so authentication will fail
        data.setStatus(UserDataRemote.STATUS_GENERATED);
        boolean authfailed = false;
        try {
            UserAuthData auth = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER), username, pwd);
        } catch (Exception e) {
            authfailed = true;
        }

        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        cat.debug("<test03FailAuthenticateUser()");
    }

    public void test04FailAuthenticateUser() throws Exception {
        cat.debug(">test04FailAuthenticateUser()");
        // user that we know exists... but we issue wrong password
        boolean authfailed = false;
        try {
            UserAuthData auth = remote.authenticateUser(new Admin(Admin.TYPE_INTERNALUSER), username, "abc123");
        } catch (Exception e) {
            authfailed = true;
        }

        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        cat.debug("<test04FailAuthenticateUser()");
    }
}
