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

package org.ejbca.core.ejb.ca.crl;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.cert.CrlExtensions;

/**
 * Tests Delta CRLs.
 *
 * @version $Id: TestDeltaCRL.java,v 1.2 2008-01-04 13:26:18 anatom Exp $
 */
public class TestDeltaCRL extends TestCase {

    private static Logger log = Logger.getLogger(TestDeltaCRL.class);
    private static Context ctx;
    private static ICreateCRLSessionHome home;
    private static ICreateCRLSessionRemote remote;
    private static ICertificateStoreSessionHome storehome;
    private static ICertificateStoreSessionRemote storeremote;
    private static IUserAdminSessionRemote usersession;
    private static ISignSessionRemote signsession;
    private static Admin admin;
    private static int caid;
    private static String cadn;
    private static KeyPair keys;
    
    private static final String USERNAME = "foo";

    /**
     * Creates a new TestCreateCRLSession object.
     *
     * @param name name
     */
    public TestDeltaCRL(String name) {
        super(name);
        CertTools.installBCProvider();
        keys = genKeys();
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        ctx = getInitialContext();

        admin = new Admin(Admin.TYPE_INTERNALUSER);

        Object obj = ctx.lookup("CreateCRLSession");
        home = (ICreateCRLSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICreateCRLSessionHome.class);
        remote = home.create();

        Object obj1 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        storeremote = storehome.create();
        
        obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();

        obj = ctx.lookup("RSASignSession");
        ISignSessionHome signhome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);
        signsession = signhome.create();

        obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        // Use Test CA created before
        CAInfo cainfo = casession.getCAInfo(admin, "TEST");
        assertNotNull("CA TEST not active. You must run TestCAs before this test");
        cadn = cainfo.getSubjectDN();
        caid = cainfo.getCAId();
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
     * creates new delta crl
     *
     * @throws Exception error
     */
    public void test01CreateNewDeltaCRL() throws Exception {
        log.debug(">test01CreateNewCRL()");
        remote.runDeltaCRL(admin, cadn);
        log.debug("<test01CreateNewCRL()");
    }

    /**
     * gets last crl
     *
     * @throws Exception error
     */
    public void test02LastDeltaCRL() throws Exception {
        log.debug(">test02LastCRL()");
        // Get number of last Delta CRL
        int number = storeremote.getLastCRLNumber(admin, cadn, true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        remote.runDeltaCRL(admin, cadn);
        int number1 = storeremote.getLastCRLNumber(admin, cadn, true);
        assertEquals(number+1, number1);
        byte[] crl1 = storeremote.getLastCRL(admin, cadn, true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number+1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be increased by two
        remote.run(admin, cadn);
        remote.runDeltaCRL(admin, cadn);
        int number2 = storeremote.getLastCRLNumber(admin, cadn, true);
        assertEquals(number1+2, number2);
        byte[] crl2 = storeremote.getLastCRL(admin, cadn, true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1+2, num2.intValue());
        log.debug("<test02LastDeltaCRL()");
    }

    /**
     * check revoked certificates
     *
     * @throws Exception error
     */
    public void test03CheckNumberofRevokedCerts() throws Exception {
        log.debug(">test03CheckNumberofRevokedCerts()");

        byte[] crl = storeremote.getLastCRL(admin, cadn, false);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        // Get number of last CRL
        Collection revfp = storeremote.listRevokedCertInfo(admin, cadn, x509crl.getThisUpdate().getTime());
        log.debug("Number of revoked certificates=" + revfp.size());
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);

        x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        int revsize = 0;
        // This is probably 0
        if (revset != null) {
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        }
        
        // Do some revoke
        X509Certificate cert = createUserAndCert();
        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);        
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new CRL again...
        remote.runDeltaCRL(admin, cadn);
        // Check that our newly signed certificate is present in a new CRL
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull("revset can not be null", revset);
        assertEquals(revsize+1, revset.size());        	
        
        log.debug("<test03CheckNumberofRevokedCerts()");
    }

    /**
     * Test revocation and un-revokation of certificates
     *
     * @throws Exception error
     */
    public void test04RevokeAndUnrevoke() throws Exception {
        log.debug(">test04RevokeAndUnrevoke()");

        X509Certificate cert = createUserAndCert();
        
        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newly signed certificate is not present in a new CRL
        byte[] crl = storeremote.getLastCRL(admin, cadn, false);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        if (revset != null) {
            Iterator iter = revset.iterator();
            while (iter.hasNext()) {
                X509CRLEntry ce = (X509CRLEntry)iter.next(); 
                assertTrue(ce.getSerialNumber().compareTo(cert.getSerialNumber()) != 0);
            }            
        } // If no revoked certificates exist at all, this test passed...

        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new delta CRL again...
        remote.runDeltaCRL(admin, cadn);
        // Check that our newly signed certificate IS present in a new Delta CRL
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull("revset can not be null", revset);
        Iterator iter = revset.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Unrevoke the certificate that we just revoked
        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.NOT_REVOKED);
        // Create a new Delta CRL again...
        remote.runDeltaCRL(admin, cadn);
        // Check that our newly signed certificate IS NOT present in the new CRL.
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        if (revset != null) {
        	iter = revset.iterator();
        	found = false;
        	while (iter.hasNext()) {
        		X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        		if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        			found = true;
        		}
        	}
        	assertFalse(found);
        } // If no revoked certificates exist at all, this test passed...

        // Check that when we revoke a certificate it will be present on the delta CRL
        // When we create a new full CRL it will be present there, and not on the next delta CRL
        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);
        // Create a new delta CRL again...
        remote.runDeltaCRL(admin, cadn);
        // Check that our newly signed certificate IS present in a new Delta CRL
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull(revset);
        iter = revset.iterator();
        found = false;
		//System.out.println(x509crl.getThisUpdate());
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
    		//System.out.println(ce);
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new Full CRL 
        remote.run(admin, cadn);
        // Check that our newly signed certificate IS present in a new Full CRL
        crl = storeremote.getLastCRL(admin, cadn, false);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull(revset);
        iter = revset.iterator();
        found = false;
		//System.out.println(x509crl.getThisUpdate());
		//System.out.println(x509crl.getThisUpdate().getTime());
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
    		//System.out.println(ce);
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Create a new Delta CRL again...
        remote.runDeltaCRL(admin, cadn);
        // Check that our newly signed certificate IS NOT present in the new Delta CRL.
        crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
		//System.out.println(x509crl.getThisUpdate());
        if (revset != null) {
        	iter = revset.iterator();
        	found = false;
        	while (iter.hasNext()) {
        		X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        		//System.out.println(ce);
        		//System.out.println(ce.getRevocationDate().getTime());
        		if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        			found = true;
        		}
        	}
        	assertFalse(found);
        } // If no revoked certificates exist at all, this test passed...
        
        log.debug("<test04RevokeAndUnrevoke()");
    }

    // 
    // Helper methods
    //
    
    private X509Certificate createUserAndCert() throws Exception {
        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin,USERNAME,"foo123","C=SE,O=AnaTom,CN=foo",null,"foo@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: "+USERNAME+", foo123, C=SE, O=AnaTom, CN=foo");
        } catch (RemoteException re) {
        	userExists = true;
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User "+USERNAME+" already exists, resetting status.");
            usersession.setUserStatus(admin,"foo",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        // user that we know exists...
        X509Certificate cert = (X509Certificate)signsession.createCertificate(admin, USERNAME, "foo123", keys.getPublic());
        assertNotNull("Failed to create certificate", cert);
        return cert;
    }
    
    /**
     * Generates a RSA key pair.
     *
     * @return KeyPair the generated key pair
     *
     */
    private static KeyPair genKeys() {
    	try {
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
            keygen.initialize(512);
            log.debug("Generating keys, please wait...");
            KeyPair rsaKeys = keygen.generateKeyPair();
            log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" +
                    ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());    		
            return rsaKeys;
    	} catch (Exception e) {
    		assertFalse(e.getMessage(), true);
    	}
    	return null;
    } // genKeys
}
