package se.anatom.ejbca.ca.auth.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import javax.ejb.DuplicateKeyException;

import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.ca.auth.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests authentication session used by signer.
 *
 * @version $Id: TestAuthenticationSession.java,v 1.3 2002-03-22 10:11:24 anatom Exp $
 */
public class TestAuthenticationSession extends TestCase {

    static Category cat = Category.getInstance( TestAuthenticationSession.class.getName() );
    private static Context ctx;
    private static IAuthenticationSessionHome home;
    private static IAuthenticationSessionRemote remote;

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

    public void test01CreateNewUser() throws Exception {
        cat.debug(">test01CreateNewUser()");
        // Make user that we know...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        boolean userExists = false;
        try {
            UserData createdata = userhome.create("foo", "foo123", "C=SE, O=AnaTom, CN=foo");
            assertNotNull("Failed to create user foo", createdata);
            createdata.setType(SecConst.USER_ENDUSER);
            createdata.setSubjectEmail("foo@anatom.se");
            cat.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (RemoteException re) {
            if (re.getCause() instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            cat.debug("user foo already exists.");
            UserDataPK pk = new UserDataPK();
            pk.username = "foo";
            UserData data = userhome.findByPrimaryKey(pk);
            data.setStatus(UserData.STATUS_NEW);
            cat.debug("Reset status to NEW");
        }
        cat.debug("<test01CreateNewUser()");
    }
    public void test02AuthenticateUser() throws Exception {
        cat.debug(">test02AuthenticateUser()");
        // user that we know exists...
        UserAuthData data = remote.authenticateUser("foo", "foo123");
        cat.debug("DN: "+data.getDN());
        assertTrue("DN is wrong", data.getDN().indexOf("foo") != -1);
        cat.debug("Email: "+data.getEmail());
        assertTrue("Email is wrong", data.getEmail().equals("foo@anatom.se"));
        cat.debug("Type: "+data.getType());
        assertTrue("Type is wrong", data.getType() == SecConst.USER_ENDUSER);
        cat.debug("<test02AuthenticateUser()");
    }

    public void test03FailAuthenticateUser() throws Exception {
        cat.debug(">test03FailAuthenticateUser()");
        // user that we know exists...
        Object obj1 = ctx.lookup("UserData");
        UserDataHome userhome = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj1, UserDataHome.class);
        UserDataPK pk = new UserDataPK();
        pk.username = "foo";
        UserData data = userhome.findByPrimaryKey(pk);
        // Set status to GENERATED so authentication will fail
        data.setStatus(UserData.STATUS_GENERATED);
        boolean authfailed = false;
        try {
            UserAuthData auth = remote.authenticateUser("foo", "foo123");
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
            UserAuthData auth = remote.authenticateUser("foo", "abc123");
        } catch (Exception e) {
            authfailed = true;
        }
        assertTrue("Authentication succeeded when it should have failed.", authfailed);
        cat.debug("<test04FailAuthenticateUser()");
    }
}
