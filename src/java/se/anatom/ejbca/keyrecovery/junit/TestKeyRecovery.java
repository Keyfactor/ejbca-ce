package se.anatom.ejbca.keyrecovery.junit;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote;
import se.anatom.ejbca.keyrecovery.KeyRecoveryData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

/**
 * Tests the key recovery modules.
 *
 * @version $Id: TestKeyRecovery.java,v 1.1 2004-03-14 13:51:43 herrvendil Exp $
 */
public class TestKeyRecovery extends TestCase {
	private static Logger log = Logger.getLogger(TestKeyRecovery.class);
    
    private IKeyRecoverySessionRemote cacheAdmin;

    private static IKeyRecoverySessionHome cacheHome;

    private static Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    private static final String user = genRandomUserName(); 
    
    private static KeyPair keypair = null;
    private static X509Certificate cert = null;
    
    /**
     * Creates a new TestLog object.
     *
     * @param name name
     */
    public TestKeyRecovery(String name) {
        super(name);
        
        // Generate test keypair and certificate.
        try{ 
          CertTools.installBCProvider();
          
          ISignSessionHome home = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(getInitialContext().lookup("RSASignSession"), ISignSessionHome.class);
          ISignSessionRemote ss = home.create();

          Object obj = getInitialContext().lookup("UserAdminSession");        
          IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);        
          IUserAdminSessionRemote usersession = userhome.create();

          String email = "test@test.se"; 
          if(!usersession.existsUser(admin,user)){
          	keypair = KeyTools.genKeys(2048);
            usersession.addUser(admin,user,"foo123", "CN=TESTKEYREC","rfc822name="+email,email,false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_P12,0,"CN=TEST".hashCode());
        
            cert =  (X509Certificate) ss.createCertificate(admin,user,"foo123",keypair.getPublic());
          }  
        }catch(Exception e){
        	System.out.println("Error Creating TestKeyRecovery instance.");
        }

    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        Context jndiContext = getInitialContext();
        if( cacheAdmin == null ) {
            if (cacheHome == null) {
                
                Object obj1 = jndiContext.lookup("KeyRecoverySession");
                cacheHome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IKeyRecoverySessionHome.class);                
                
            }

            cacheAdmin = cacheHome.create();
        }


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


    /**
     * tests adding a keypair and checks if it can be read again.
     *
     * @throws Exception error
     */
    public void test01AddKeyPair() throws Exception {
        log.debug(">test01AddKeyPair()");
        CertTools.installBCProvider(); 
        cacheAdmin.addKeyRecoveryData(admin,cert,user,keypair);
        
        assertTrue("Couldn't save key's in database",cacheAdmin.existsKeys(admin,cert));

        
        log.debug("<test01AddKeyPair()");
    }
    
    /**
     * tests marks the keypair in database and recovers it.
     *
     * @throws Exception error
     */
    public void test02MarkAndRecoverKeyPair() throws Exception {
        log.debug(">test02MarkAndRecoverKeyPair()");
        CertTools.installBCProvider();
        assertTrue("Couldn't mark user for recovery in database", !cacheAdmin.isUserMarked(admin,user));
        cacheAdmin.markAsRecoverable(admin,cert);
        assertTrue("Couldn't mark user for recovery in database", cacheAdmin.isUserMarked(admin,user));
        KeyRecoveryData data = cacheAdmin.keyRecovery(admin,user);
        
        assertTrue("Couldn't recover keys from database", Arrays.equals(data.getKeyPair().getPrivate().getEncoded(), keypair.getPrivate().getEncoded()));
                
        log.debug("<test02MarkAndRecoverKeyPair()");
    }
    
    /**
     * tests removes all keydata.
     *
     * @throws Exception error
     */
    public void test03RemoveKeyPair() throws Exception {
        log.debug(">test03RemoveKeyPair()");
        CertTools.installBCProvider();
        cacheAdmin.removeKeyRecoveryData(admin,cert);
        assertTrue("Couldn't remove keys from database", !cacheAdmin.existsKeys(admin,cert));
        
        log.debug("<test03RemoveKeyPair()");
    }
    
    private static String genRandomUserName() {
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
}
