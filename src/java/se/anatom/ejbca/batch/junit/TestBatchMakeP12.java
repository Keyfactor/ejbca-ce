package se.anatom.ejbca.batch.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;
import java.io.File;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import se.anatom.ejbca.batch.*;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests the batch making of soft cards.
 *
 * @version $Id: TestBatchMakeP12.java,v 1.3 2002-01-08 09:45:08 anatom Exp $
 */
public class TestBatchMakeP12 extends TestCase {

    static Category cat = Category.getInstance( TestBatchMakeP12.class.getName() );
    private static Context ctx;
    private static UserDataHome home;
    private static String username;
    private static String username1;
    private static String pwd;
    private static String pwd1;

    public TestBatchMakeP12(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("UserData");
        home = (UserDataHome) javax.rmi.PortableRemoteObject.narrow(obj, UserDataHome.class);

        cat.debug("<setUp()");
    }
    protected void tearDown() throws Exception {
    }
    private Context getInitialContext() throws NamingException {
        System.out.println(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        System.out.println("<getInitialContext");
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
        System.out.println("Generated random username: username =" + username);
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
        System.out.println("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd

    public void test01CreateNewUsers() throws Exception {
        cat.debug(">test01CreateNewUser()");
            UserData data1=null;
            String username = genRandomUserName();
            data1 = home.create(username, "foo123", "C=SE, O=AnaTom, CN="+username);
            assertNotNull("Failed to create user "+username, data1);
            data1.setType(SecConst.USER_ENDUSER);
            data1.setSubjectEmail(username+"@anatom.se");
            data1.setClearPassword("foo123");
            System.out.println("created "+username+ ", pwd=foo123");


            UserData data4=null;
            String username1 = genRandomUserName();
            data4 = home.create(username1, "foo123", "C=SE, O=AnaTom, CN="+username);
            assertNotNull("Failed to create user "+username, data4);
            data4.setType(SecConst.USER_ENDUSER);
            data4.setSubjectEmail(username+"@anatom.se");
            data4.setClearPassword("foo123");
            System.out.println("created "+username1+ ", pwd=foo123");

        cat.debug("<test01CreateNewUsers()");
    }
    public void test02MakeP12() throws Exception {
        cat.debug(">test02MakeP12()");
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        //System.out.println("tempdir="+tmpfile.getParent());
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createAllNew();
        cat.debug("<test02MakeP12()");
    }

}
