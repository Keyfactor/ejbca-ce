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
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Set;

import javax.ejb.DuplicateKeyException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;
import org.ejbca.util.cert.CrlExtensions;
import org.ejbca.util.keystore.KeyTools;

/**
 * Tests Delta CRLs.
 *
 * @version $Id$
 */
public class DeltaCRLTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(DeltaCRLTest.class);
    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    private static int caid;
    private static CA ca;
    private static KeyPair keys;
    
    private static final String USERNAME = "foo";
    
    private CreateCRLSessionRemote createCrlSession = InterfaceCache.getCrlSession();
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private SignSessionRemote signSession = InterfaceCache.getSignSession();
    private UserAdminSessionRemote userAdminSession = InterfaceCache.getUserAdminSession();
    
    /**
     * Creates a new TestCreateCRLSession object.
     *
     * @param name name
     */
    public DeltaCRLTest(String name) {
        super(name);
        CryptoProviderTools.installBCProvider();
        keys = genKeys();
        createTestCA();
    }

    public void setUp() throws Exception {
        log.trace(">setUp()");
        // Use Test CA created before
        caid = getTestCAId();
        ca = caAdminSessionRemote.getCA(admin, caid);
        assertNotNull("CA TEST not active. You must run TestCAs before this test", ca.getSubjectDN());
        log.trace("<setUp()");
    }

    public void tearDown() throws Exception { }

    public void test01CreateNewDeltaCRL() throws Exception {
        log.trace(">test01CreateNewCRL()");
        createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        log.trace("<test01CreateNewCRL()");
    }

    public void test02LastDeltaCRL() throws Exception {
        log.trace(">test02LastCRL()");
        // Get number of last Delta CRL
        int number = createCrlSession.getLastCRLNumber(admin, ca.getSubjectDN(), true);
        log.debug("Last CRLNumber = " + number);
        byte[] crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        BigInteger num = CrlExtensions.getCrlNumber(x509crl);
        assertEquals(number, num.intValue());
        // Create a new CRL again to see that the number increases
        createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        int number1 = createCrlSession.getLastCRLNumber(admin, ca.getSubjectDN(), true);
        assertEquals(number+1, number1);
        byte[] crl1 = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
        X509CRL x509crl1 = CertTools.getCRLfromByteArray(crl1);
        BigInteger num1 = CrlExtensions.getCrlNumber(x509crl1);
        assertEquals(number+1, num1.intValue());
        // Now create a normal CRL and a deltaCRL again. CRLNUmber should now be increased by two
        createCrlSession.run(admin, ca);
        createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        int number2 = createCrlSession.getLastCRLNumber(admin, ca.getSubjectDN(), true);
        assertEquals(number1+2, number2);
        byte[] crl2 = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
        X509CRL x509crl2 = CertTools.getCRLfromByteArray(crl2);
        BigInteger num2 = CrlExtensions.getCrlNumber(x509crl2);
        assertEquals(number1+2, num2.intValue());
        log.trace("<test02LastDeltaCRL()");
    }

    public void test03CheckNumberofRevokedCerts() throws Exception {
        // check revoked certificates
        log.trace(">test03CheckNumberofRevokedCerts()");

        byte[] crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), false);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        // Get number of last CRL
        Collection revfp = certificateStoreSession.listRevokedCertInfo(admin, ca.getSubjectDN(), x509crl.getThisUpdate().getTime());
        log.debug("Number of revoked certificates=" + revfp.size());
        crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
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
        certificateStoreSession.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, null);        
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new CRL again...
        crl = createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        // Check that our newly signed certificate is present in a new CRL
        //crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull("revset can not be null", revset);
        assertEquals(revsize+1, revset.size());        	
        
        log.trace("<test03CheckNumberofRevokedCerts()");
    }

    public void test04RevokeAndUnrevoke() throws Exception {
        // Test revocation and un-revokation of certificates
        log.trace(">test04RevokeAndUnrevoke()");

        X509Certificate cert = createUserAndCert();
        
        // Create a new CRL again...
        createCrlSession.run(admin, ca);
        // Check that our newly signed certificate is not present in a new CRL
        byte[] crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), false);
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set<? extends X509CRLEntry> revset = x509crl.getRevokedCertificates();
        if (revset != null) {
            Iterator<? extends X509CRLEntry> iter = revset.iterator();
            while (iter.hasNext()) {
                X509CRLEntry ce = iter.next(); 
                assertTrue(ce.getSerialNumber().compareTo(cert.getSerialNumber()) != 0);
            }            
        } // If no revoked certificates exist at all, this test passed...

        certificateStoreSession.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD, null);
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new delta CRL again...
        crl = createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        // Check that our newly signed certificate IS present in a new Delta CRL
        //crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull("revset can not be null", revset);
        Iterator<? extends X509CRLEntry> iter = revset.iterator();
        boolean found = false;
        while (iter.hasNext()) {
            X509CRLEntry ce = iter.next(); 
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Unrevoke the certificate that we just revoked
        certificateStoreSession.revokeCertificate(admin, cert, null, RevokedCertInfo.NOT_REVOKED, null);
        // Create a new Delta CRL again...
        createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        // Check that our newly signed certificate IS NOT present in the new CRL.
        crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
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
        certificateStoreSession.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE, null);
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new delta CRL again...
        crl = createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        // Check that our newly signed certificate IS present in a new Delta CRL
        //crl = storeremote.getLastCRL(admin, cadn, true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull(revset);
        iter = revset.iterator();
        found = false;
		//log.debug(x509crl.getThisUpdate());
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
    		//log.debug(ce);
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new Full CRL 
        createCrlSession.run(admin, ca);
        // Check that our newly signed certificate IS present in a new Full CRL
        crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), false);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull(revset);
        iter = revset.iterator();
        found = false;
		//log.debug(x509crl.getThisUpdate());
		//log.debug(x509crl.getThisUpdate().getTime());
        while (iter.hasNext()) {
            X509CRLEntry ce = (X509CRLEntry)iter.next(); 
    		//log.debug(ce);
        	if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        		found = true;
        		// TODO: verify the reason code
        	}
        }
        assertTrue(found);
        
        // Sleep 1 second so we don't issue the next CRL at the exact same time as the revocation 
        Thread.sleep(1000);
        // Create a new Delta CRL again...
        createCrlSession.runDeltaCRL(admin, ca, -1, -1);
        // Check that our newly signed certificate IS NOT present in the new Delta CRL.
        crl = createCrlSession.getLastCRL(admin, ca.getSubjectDN(), true);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
		//log.debug(x509crl.getThisUpdate());
        if (revset != null) {
        	iter = revset.iterator();
        	found = false;
        	while (iter.hasNext()) {
        		X509CRLEntry ce = (X509CRLEntry)iter.next(); 
        		//log.debug(ce);
        		//log.debug(ce.getRevocationDate().getTime());
        		if (ce.getSerialNumber().compareTo(cert.getSerialNumber()) == 0) {
        			found = true;
        		}
        	}
        	assertFalse(found);
        } // If no revoked certificates exist at all, this test passed...
        
        log.trace("<test04RevokeAndUnrevoke()");
    }

    public void test99RemoveTestCA() throws Exception {
    	removeTestCA();    	
    }
    
    // 
    // Helper methods
    //
    
    private X509Certificate createUserAndCert() throws Exception {
        // Make user that we know...
        boolean userExists = false;
    	UserDataVO user = new UserDataVO(USERNAME, "C=SE,O=AnaTom,CN=foo", caid, null, "foo@anatom.se",SecConst.USER_ENDUSER, SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
    	user.setPassword("foo123");
        try {
        	userAdminSession.addUser(admin, user, false);
            //usersession.addUser(admin,USERNAME,"foo123","C=SE,O=AnaTom,CN=foo",null,"foo@anatom.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: "+USERNAME+", foo123, C=SE, O=AnaTom, CN=foo");
       
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }
        if (userExists) {
            log.info("User "+USERNAME+" already exists, resetting status.");
            userAdminSession.changeUser(admin, user, false);
            userAdminSession.setUserStatus(admin,"foo",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        // user that we know exists...
        X509Certificate cert = (X509Certificate)signSession.createCertificate(admin, USERNAME, "foo123", keys.getPublic());
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
    		return KeyTools.genKeys("512", "RSA");
    	} catch (Exception e) {
    		assertFalse(e.getMessage(), true);
    	}
    	return null;
    }
}
