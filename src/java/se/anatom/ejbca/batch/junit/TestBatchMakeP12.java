package se.anatom.ejbca.batch.junit;

import java.util.*;
import java.io.File;

import javax.naming.Context;
import javax.naming.NamingException;

import se.anatom.ejbca.batch.*;
import se.anatom.ejbca.ra.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.Logger;
import junit.framework.*;


/** Tests the batch making of soft cards.
 *
 * @version $Id: TestBatchMakeP12.java,v 1.19 2003-02-12 11:23:14 scop Exp $
 */

public class TestBatchMakeP12 extends TestCase {

    private static Logger log = Logger.getLogger(TestBatchMakeP12.class);
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
        log.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("UserAdminSession");
        home = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
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
        Random rand = new Random(new Date().getTime()+4812);

        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd

    public void test01CreateNewUsers() throws Exception {
        log.debug(">test01CreateNewUser()");
        IUserAdminSessionRemote data1=null;
        String username = genRandomUserName();

        data1 = home.create();
        Object o = null;
        try{
          data1.addUser(new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER), username, "foo123", "C=SE, O=AnaTom, CN="+username, "", username+"@anatom.se",  false,
                        SecConst.EMPTY_ENDENTITYPROFILE, SecConst.PROFILE_NO_CERTIFICATEPROFILE,
                        false, false, SecConst.TOKEN_SOFT_P12,0);
          data1.setClearTextPassword(new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER), username,"foo123");
          o = new String("");
        }catch(Exception e){
          assertNotNull("Failed to create user "+username, o);
        }

        log.debug("created "+username+ ", pwd=foo123");

        String username1 = genRandomUserName();
        o = null;
        try{
          data1.addUser(new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER), username1, "foo123", "C=SE, O=AnaTom, CN="+username1, "",username1+"@anatom.se", false,
                        SecConst.EMPTY_ENDENTITYPROFILE, SecConst.PROFILE_NO_CERTIFICATEPROFILE,
                        false, false, SecConst.TOKEN_SOFT_P12,0);
          data1.setClearTextPassword(new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER), username1,"foo123");
          o = new String("");
        }catch(Exception e){
          assertNotNull("Failed to create user "+username1, o);
        }
        log.debug("created "+username1+ ", pwd=foo123");
        log.debug("<test01CreateNewUsers()");
    }

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
