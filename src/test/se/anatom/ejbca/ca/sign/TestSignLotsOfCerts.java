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

package se.anatom.ejbca.ca.sign;

import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserDataConstants;
import se.anatom.ejbca.util.CertTools;


/** This is a manual test that requires some manual set up and configuration.
 * -caid should a CA that has "finish user" set to off
 * -the users performancefoono1-10 should not exist in the database
 * 
 *
 * @version $Id: TestSignLotsOfCerts.java,v 1.4 2005-12-17 10:35:50 anatom Exp $
 */
public class TestSignLotsOfCerts extends TestCase {
    private static Logger log = Logger.getLogger(TestSignLotsOfCerts.class);
    public static Context ctx;
    private static IUserAdminSessionRemote usersession;
    public static KeyPair keys;
    private static int caid = 0;
    public Admin admin;

    /**
     * Creates a new TestSignSession object.
     *
     * @param name name
     */
    public TestSignLotsOfCerts(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        // Install BouncyCastle provider
        CertTools.installBCProvider();

        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

        caid = -1688117755; // EDIT THIS

        ctx = getInitialContext();
        Object obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();
        
        keys = genKeys();

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
     * Generates a RSA key pair.
     *
     * @return KeyPair the generated key pair
     *
     * @throws Exception if en error occurs...
     */
    private static KeyPair genKeys() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(1024);
        log.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" +
                ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());

        return rsaKeys;
    } // genKeys

    private void newUser(String post) throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin,"performancefoo"+post,"foo123","C=SE,O=AnaTom,OU=Performance Test,CN=performancefoo",null,"performancefoo@foo.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: performancefoo"+post+", foo123, C=SE, O=AnaTom, OU=Performance Test,CN=performancefoo");
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User performancefoo already exists, resetting status.");
            usersession.setUserStatus(admin,"performancefoo"+post,UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }

    }
    /**
     * creates new user
     *
     * @throws Exception if en error occurs...
     */
    public void test01CreateNewUser() throws Exception {
        log.debug(">test01CreateNewUser()");
        newUser("no1");
        newUser("no2");
        newUser("no3");
        newUser("no4");
        newUser("no5");
        newUser("no6");
        newUser("no7");
        newUser("no8");
        newUser("no9");
        newUser("no10");
        log.debug("<test01CreateNewUser()");
    }

    /**
     * creates cert
     *
     * @throws Exception if en error occurs...
     */
    public void test03SignLotsOfCerts() throws Exception {
        log.debug(">test03SignLotsOfCerts()");

		long before = System.currentTimeMillis();
        Thread no1 = new Thread(new SignTester(),"no1");
        Thread no2 = new Thread(new SignTester(),"no2");
        Thread no3 = new Thread(new SignTester(),"no3");
        Thread no4 = new Thread(new SignTester(),"no4");
        Thread no5 = new Thread(new SignTester(),"no5");
        Thread no6 = new Thread(new SignTester(),"no6");
        Thread no7 = new Thread(new SignTester(),"no7");
        Thread no8 = new Thread(new SignTester(),"no8");
        Thread no9 = new Thread(new SignTester(),"no9");
        Thread no10 = new Thread(new SignTester(),"no10");
        no1.start();
        System.out.println("Started no1");
        no2.start();
        System.out.println("Started no2");
        no3.start();
        System.out.println("Started no3");
        no4.start();
        System.out.println("Started no4");
        no5.start();
        System.out.println("Started no5");
        no6.start();
        System.out.println("Started no6");
        no7.start();
        System.out.println("Started no7");
        no8.start();
        System.out.println("Started no8");
        no9.start();
        System.out.println("Started no9");
        no10.start();
        System.out.println("Started no10");
        no1.join();
        no2.join();
        no3.join();
        no4.join();
        no5.join();
        no6.join();
        no7.join();
        no8.join();
        no9.join();
        no10.join();
		long after = System.currentTimeMillis();
		long diff = after - before;
        System.out.println("All threads finished. Total time: "+diff);
        //FileOutputStream fos = new FileOutputStream("testcert.crt");
        //fos.write(cert.getEncoded());
        //fos.close();
        log.debug("<test03SignLotsOfCerts()");
    }
    
    private class SignTester implements Runnable {
    	public void run() {
            try {
                Object obj = ctx.lookup("RSASignSession");
                ISignSessionHome rsahome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
                ISignSessionRemote rsaremote = rsahome.create();
                String user = "performancefoo"+Thread.currentThread().getName();
				long before = System.currentTimeMillis();
				for (int i = 0; i<1000;i++) {
			        // user that we know exists...
				    X509Certificate cert = (X509Certificate) rsaremote.createCertificate(admin, user, "foo123", keys.getPublic());
				    assertNotNull("Misslyckades skapa cert", cert);
				    if ((i % 100) == 0) {
				    	long mellantid = System.currentTimeMillis() - before;
				    	System.out.println(Thread.currentThread().getName()+" har skapat "+i+", tid="+mellantid);
				    	
				    }
				}
				long after = System.currentTimeMillis();
				long diff = after - before;
				System.out.println("Tidsåtgång ("+Thread.currentThread().getName()+"): "+diff);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}    		
    	}
    }
}
