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
 * @version $Id: TestBatchMakeP12.java,v 1.9 2002-07-28 23:27:48 herrvendil Exp $
 */

public class TestBatchMakeP12 extends TestCase {

    static Category cat = Category.getInstance( TestBatchMakeP12.class.getName() );
    private static Context ctx;
    private static IUserAdminSessionHome home;
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
        Object obj = ctx.lookup("UserAdminSession");
        home = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
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

    public void test01CreateNewUsers() throws Exception {
        cat.debug(">test01CreateNewUser()");
        IUserAdminSessionRemote data1=null;
        String username = genRandomUserName();
  
        data1 = home.create();
        Object o = null;       
        try{
          data1.addUser(username, "foo123", "C=SE, O=AnaTom, CN="+username, username+"@anatom.se", SecConst.USER_ENDUSER,
                        UserAdminData.NO_PROFILE, UserAdminData.NO_CERTIFICATETYPE);
          data1.setClearTextPassword(username,"foo123");
          o = new String(""); 
        }catch(Exception e){
          assertNotNull("Failed to create user "+username, o);            
        }

        cat.debug("created "+username+ ", pwd=foo123");

        String username1 = genRandomUserName();
        o = null;
        try{
          data1.addUser(username1, "foo123", "C=SE, O=AnaTom, CN="+username1, username1+"@anatom.se", SecConst.USER_ENDUSER,
                        UserAdminData.NO_PROFILE, UserAdminData.NO_CERTIFICATETYPE);
          data1.setClearTextPassword(username1,"foo123");   
          o = new String("");
        }catch(Exception e){  
          assertNotNull("Failed to create user "+username1, o);
        }
        cat.debug("created "+username1+ ", pwd=foo123");
        cat.debug("<test01CreateNewUsers()");
    }

    public void test02MakeP12() throws Exception {
        cat.debug(">test02MakeP12()");
        BatchMakeP12 makep12 = new BatchMakeP12();
        File tmpfile = File.createTempFile("ejbca", "p12");
        //System.out.println("tempdir="+tmpfile.getParent());
        makep12.setMainStoreDir(tmpfile.getParent());
        makep12.createPEM(true);
        makep12.createAllNew();
        cat.debug("<test02MakeP12()");
    }

}

