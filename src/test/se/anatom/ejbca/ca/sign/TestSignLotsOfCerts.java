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

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.util.CertTools;


/** This is a performance test:
 * - 10 threads generates 1000 certificates each with 1024 bit public key
 * - CA uses 2048 bit signature key
 * - total time for certificate generation is counted to get number of certificates generated per second
 * 
 * 
 *
 * @version $Id: TestSignLotsOfCerts.java,v 1.9 2008-04-09 21:54:21 anatom Exp $
 */
public class TestSignLotsOfCerts extends TestCase {
    private static Logger log = Logger.getLogger(TestSignLotsOfCerts.class);
    public static Context ctx;
    private static IUserAdminSessionRemote usersession;
    private static ICAAdminSessionRemote cacheAdmin;
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

        caid = "CN=TESTPERF1".hashCode();

        ctx = getInitialContext();
        Object obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();
        
        if (cacheAdmin == null) {
        	Context jndiContext = getInitialContext();
        	Object obj1 = jndiContext.lookup("CAAdminSession");
        	ICAAdminSessionHome home = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
        	cacheAdmin = home.create();
        }


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
    private void deleteUser(String post) throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.deleteUser(admin, "performancefoo"+post);
            log.debug("deleted user: performancefoo"+post);
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        }
    }
    
    public void test00AddRSACA() throws Exception {
        boolean ret = false;
        try {

            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, "CN=TESTPERF1".hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setSignKeySpec("2048");
            catokeninfo.setEncKeySpec("2048");
            catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + "CN=TESTPERF1",
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));
            extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_INACTIVE,
                    "CN=XKMSCertificate, " + "CN=TESTPERF1",
                    "",
                    "1024",
                    CATokenConstants.KEYALGORITHM_RSA));


            X509CAInfo cainfo = new X509CAInfo("CN=TESTPERF1",
                    "TESTPERF1", SecConst.CA_ACTIVE, new Date(),
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    3650,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "JUnit RSA CA",
                    -1, null,
                    null, // PolicyId
                    24, // CRLPeriod
                    0, // CRLIssueInterval
                    10, // CRLOverlapTime
                    10, // Delta CRL period
                    new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    null, // defaultcrldistpoint 
                    null, // defaultcrlissuer 
                    null, // defaultocsplocator
                    null, // defaultfreshestcrl
                    false, // Finish User
                    extendedcaservices,
                    false, // use default utf8 settings
                    new ArrayList(), // Approvals Settings
                    1, // Number of Req approvals
                    false, // Use UTF8 subject DN by default
            		true, // Use LDAP DN order by default
            		false, // Use CRL Distribution Point on CRL
            		false,  // CRL Distribution Point on CRL critical
            		true // Include in Health Check
            		);

            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TESTPERF1");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TESTPERF1"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TESTPERF1"));
            PublicKey pk = cert.getPublicKey();
            if (pk instanceof RSAPublicKey) {
            	RSAPublicKey rsapk = (RSAPublicKey) pk;
				assertEquals(rsapk.getAlgorithm(), "RSA");
			} else {
				assertTrue("Public key is not EC", false);
			}
            assertTrue("CA is not valid for the specified duration.",cert.getNotAfter().after(new Date(new Date().getTime()+10*364*24*60*60*1000L)) && cert.getNotAfter().before(new Date(new Date().getTime()+10*366*24*60*60*1000L)));
            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }

        assertTrue("Creating RSA CA failed", ret);
    }

    /**
     * creates new user
     *
     * @throws Exception if an error occurs...
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
        System.out.println("All threads finished. Total time: "+diff+" ms");
        int noOfGeneratedCerts = (10 * SignTester.NO_CERTS);
        System.out.println("Generated "+noOfGeneratedCerts+" certificates in total.");
        BigDecimal d = new BigDecimal(diff).divide(new BigDecimal(1000));
        BigDecimal noCerts = new BigDecimal(noOfGeneratedCerts).divide(d, 2, RoundingMode.UP);
        System.out.println("Performance is "+ noCerts.intValue() +" certs/sec.");
        //FileOutputStream fos = new FileOutputStream("testcert.crt");
        //fos.write(cert.getEncoded());
        //fos.close();
        log.debug("<test03SignLotsOfCerts()");
    }
    
    public void test99CleanUp() throws Exception {
        boolean ret = false;
        try {
            cacheAdmin.removeCA(admin, "CN=TESTPERF1".hashCode());
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing TESTPERF1 CA failed", ret);
        deleteUser("no1");
        deleteUser("no2");
        deleteUser("no3");
        deleteUser("no4");
        deleteUser("no5");
        deleteUser("no6");
        deleteUser("no7");
        deleteUser("no8");
        deleteUser("no9");
        deleteUser("no10");
    }

    private class SignTester implements Runnable {
    	
    	public static final int NO_CERTS=1000;
    	
    	public void run() {
            try {
                Object obj = ctx.lookup("RSASignSession");
                ISignSessionHome rsahome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
                ISignSessionRemote rsaremote = rsahome.create();
                String user = "performancefoo"+Thread.currentThread().getName();
				long before = System.currentTimeMillis();
				for (int i = 0; i<NO_CERTS;i++) {
			        // user that we know exists...
				    X509Certificate cert = (X509Certificate) rsaremote.createCertificate(admin, user, "foo123", keys.getPublic());
				    assertNotNull("Failed to create certificate", cert);
				    if ((i % 100) == 0) {
				    	long mellantid = System.currentTimeMillis() - before;
				    	System.out.println(Thread.currentThread().getName()+" has generated "+i+", time="+mellantid);
				    	
				    }
				}
				long after = System.currentTimeMillis();
				long diff = after - before;
				System.out.println("Time used ("+Thread.currentThread().getName()+"): "+diff);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}    		
    	}
    }
}
