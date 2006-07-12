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

package se.anatom.ejbca.ca.crl;

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
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
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
 * Tests CRL session (agentrunner and certificatesession).
 *
 * @version $Id: TestCreateCRLSession.java,v 1.4 2006-07-12 16:18:52 anatom Exp $
 */
public class TestCreateCRLSession extends TestCase {

    private static Logger log = Logger.getLogger(TestCreateCRLSession.class);
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

    /**
     * Creates a new TestCreateCRLSession object.
     *
     * @param name name
     */
    public TestCreateCRLSession(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        CertTools.installBCProvider();

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
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer) iter.next()).intValue();
            CAInfo cainfo = casession.getCAInfo(admin, caid);
            cadn = cainfo.getSubjectDN();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
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
     * creates new crl
     *
     * @throws Exception error
     */
    public void test01CreateNewCRL() throws Exception {
        log.debug(">test01CreateNewCRL()");
        remote.run(admin, cadn);
        log.debug("<test01CreateNewCRL()");
    }

    /**
     * gets last crl
     *
     * @throws Exception error
     */
    public void test02LastCRL() throws Exception {
        log.debug(">test02LastCRL()");
        // Get number of last CRL
        int number = storeremote.getLastCRLNumber(admin, cadn);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        // Create a new CRL again to see that the number increases
        remote.run(admin, cadn);
        int number1 = storeremote.getLastCRLNumber(admin, cadn);
        assertEquals(number+1, number1);
        byte[] crl1 = storeremote.getLastCRL(admin, cadn);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(num.intValue()+1, num1.intValue());
        log.debug("<test02LastCRL()");
    }

    /**
     * check revoked certificates
     *
     * @throws Exception error
     */
    public void test03CheckNumberofRevokedCerts() throws Exception {
        log.debug(">test03CheckNumberofRevokedCerts()");

        // Get number of last CRL
        Collection revfp = storeremote.listRevokedCertificates(admin, cadn);
        log.debug("Number of revoked certificates=" + revfp.size());
        byte[] crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);

        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        int revsize = 0;

        if (revset != null) {
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        }
        log.debug("<test03CheckNumberofRevokedCerts()");
    }

    /**
     * Test revocation and un-revokation of certificates
     *
     * @throws Exception error
     */
    public void test04RevokeAndUnrevoke() throws Exception {
        log.debug(">test04RevokeAndUnrevoke()");

        // Make user that we know...
        boolean userExists = false;
        try {
            usersession.addUser(admin,"foo","foo123","C=SE,O=AnaTom,CN=foo",null,"foo@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User foo already exists, resetting status.");
            usersession.setUserStatus(admin,"foo",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        KeyPair keys = genKeys();

        // user that we know exists...
        X509Certificate cert = (X509Certificate)signsession.createCertificate(admin, "foo", "foo123", keys.getPublic());
        assertNotNull("Misslyckades skapa cert", cert);
        log.debug("Cert=" + cert.toString());

        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newloy signed certificate is not present in a new CRL
        byte[] crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        Iterator iter = revset.iterator();
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	assertTrue(ce.getSerialNumber().compareTo(cert.getSerialNumber()) != 0);
        }

        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD);
        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newly signed certificate IS present in a new CRL
        crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        iter = revset.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.NOT_REVOKED);
        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newly signed certificate IS NOT present in the new CRL.
        crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        iter = revset.iterator();
        found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        	}
        }
        assertFalse(found);

        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);
        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newly signed certificate IS present in a new CRL
        crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        iter = revset.iterator();
        found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);

        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.NOT_REVOKED);
        // Create a new CRL again...
        remote.run(admin, cadn);
        // Check that our newly signed certificate is present in the new CRL, because the revocation reason
        // was not CERTIFICATE_HOLD, we can olny unrevoke certificates that are on hold.
        crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        iter = revset.iterator();
        found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        	}
        }
        assertTrue(found);
        log.debug("<test04RevokeAndUnrevoke()");
    }

    // 
    // Helper methods
    //
    
    /**
     * Generates a RSA key pair.
     *
     * @return KeyPair the generated key pair
     *
     * @throws Exception if en error occurs...
     */
    private static KeyPair genKeys() throws Exception {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(512);
        log.debug("Generating keys, please wait...");
        KeyPair rsaKeys = keygen.generateKeyPair();
        log.debug("Generated " + rsaKeys.getPrivate().getAlgorithm() + " keys with length" +
                ((RSAPrivateKey) rsaKeys.getPrivate()).getModulus().bitLength());

        return rsaKeys;
    } // genKeys
}
