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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import javax.ejb.DuplicateKeyException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.util.CertTools;
import org.ejbca.util.cert.CrlExtensions;

/**
 * Tests CRL session (agentrunner and certificatesession).
 *
 * @version $Id: TestCreateCRLSession.java,v 1.3 2008-01-18 15:08:25 nponte Exp $
 */
public class TestCreateCRLSession extends TestCase {

	private static Logger log = Logger.getLogger(TestCreateCRLSession.class);
	private static Context ctx;
	private static ICreateCRLSessionHome home;
	private static ICreateCRLSessionRemote crlSession;
	private static ICertificateStoreSessionHome storehome;
	private static ICertificateStoreSessionRemote storeremote;
	private static ICAAdminSessionRemote casession;
	private static IUserAdminSessionRemote usersession;
	private static ISignSessionRemote signsession;
	private static IRaAdminSessionRemote rasession;
	private static Admin admin;
	private static int caid;
	private static String cadn;
	private static final String TESTUSERNAME = "TestCreateCRLSessionUser";
	private static final String TESTPROFILE = "TestCreateCRLSessionProfile";	

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
		crlSession = home.create();

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
		casession = cahome.create();
		Collection caids = casession.getAvailableCAs(admin);
		Iterator iter = caids.iterator();
		if (iter.hasNext()) {
			caid = ((Integer) iter.next()).intValue();
			CAInfo cainfo = casession.getCAInfo(admin, caid);
			cadn = cainfo.getSubjectDN();
		} else {
			assertTrue("No active CA! Must have at least one active CA to run tests!", false);
		}

		obj = ctx.lookup(IRaAdminSessionHome.JNDI_NAME);
		IRaAdminSessionHome raadminhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IRaAdminSessionHome.class);
		rasession = raadminhome.create(); 

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
		crlSession.run(admin, cadn);
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
		int number = storeremote.getLastCRLNumber(admin, cadn, false);
		log.debug("Last CRLNumber = " + number);
		byte[] crl = storeremote.getLastCRL(admin, cadn, false);
		assertNotNull("Could not get CRL", crl);
		X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
		BigInteger num = CrlExtensions.getCrlNumber(x509crl);
		// Create a new CRL again to see that the number increases
		crlSession.run(admin, cadn);
		int number1 = storeremote.getLastCRLNumber(admin, cadn, false);
		assertEquals(number+1, number1);
		byte[] crl1 = storeremote.getLastCRL(admin, cadn, false);
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
		Collection revfp = storeremote.listRevokedCertInfo(admin, cadn, -1);
		log.debug("Number of revoked certificates=" + revfp.size());
		byte[] crl = storeremote.getLastCRL(admin, cadn, false);
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
        	userExists = true;
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
        crlSession.run(admin, cadn);
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
        // Create a new CRL again...
        crlSession.run(admin, cadn);
        // Check that our newly signed certificate IS present in a new CRL
        crl = storeremote.getLastCRL(admin, cadn, false);
        assertNotNull("Could not get CRL", crl);
        x509crl = CertTools.getCRLfromByteArray(crl);
        revset = x509crl.getRevokedCertificates();
        assertNotNull(revset);
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
        // Create a new CRL again...
        crlSession.run(admin, cadn);
        // Check that our newly signed certificate IS NOT present in the new CRL.
        crl = storeremote.getLastCRL(admin, cadn, false);
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

        storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE);
        // Create a new CRL again...
        crlSession.run(admin, cadn);
        // Check that our newly signed certificate IS present in a new CRL
        crl = storeremote.getLastCRL(admin, cadn, false);
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
        crlSession.run(admin, cadn);
        // Check that our newly signed certificate is present in the new CRL, because the revocation reason
        // was not CERTIFICATE_HOLD, we can only un-revoke certificates that are on hold.
        crl = storeremote.getLastCRL(admin, cadn, false);
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

	/**
	 * Test Overflow of CRL Period
	 *
	 * @throws Exception error
	 */
	public void test05CRLPeriodOverflow() throws Exception {
		log.debug(">test05CRLPeriodOverflow()");
		// Fetch CAInfo and save CRLPeriod
		CAInfo cainfo = casession.getCAInfo(admin, caid);
		int tempCRLPeriod = cainfo.getCRLPeriod();
		try {
			// Create a user that Should be revoked
			boolean userExists = false;
			try {
				int certprofileid = 0;
				// add a Certificate Profile with overridable validity
				try {
					CertificateProfile certProfile = new CertificateProfile();
					certProfile.setAllowValidityOverride(true);
					storeremote.addCertificateProfile(admin, TESTPROFILE, certProfile);
				} catch (CertificateProfileExistsException cpeee) {
				} 
				certprofileid = storeremote.getCertificateProfileId(admin, TESTPROFILE);
				assertTrue(certprofileid != 0);
				// add End Entity Profile with validity limitations
				EndEntityProfile profile;
				try {
					rasession.removeEndEntityProfile(admin, TESTPROFILE);
					profile = new EndEntityProfile();
					profile.setUse(EndEntityProfile.ENDTIME, 0, true);
					profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD,0,false);
					profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD,0,EndEntityProfile.FALSE);
					profile.setValue(EndEntityProfile.AVAILCAS, 0, new Integer(caid).toString());
					profile.setUse(EndEntityProfile.STARTTIME, 0, true);
					profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, new Integer(certprofileid).toString());
					profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, new Integer(certprofileid).toString());
					rasession.addEndEntityProfile(admin, TESTPROFILE, profile);
				} catch (EndEntityProfileExistsException pee) {
				}
				// Create a new user
				ExtendedInformation ei = new ExtendedInformation();
				ei.setCustomData(EndEntityProfile.STARTTIME, "0:00:00");
				ei.setCustomData(EndEntityProfile.ENDTIME, "0:00:50");
				UserDataVO userdata = new UserDataVO(TESTUSERNAME, "CN="+TESTUSERNAME, caid, "","foo@bar.se",  UserDataConstants.STATUS_NEW, 
						SecConst.USER_ENDUSER, rasession.getEndEntityProfileId(admin, TESTPROFILE), 
						certprofileid, new Date(), new Date() , SecConst.TOKEN_SOFT_PEM , 0, ei);
				userdata.setPassword("foo123");
				try {
					usersession.revokeAndDeleteUser(admin, TESTUSERNAME, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
				} catch (NotFoundException nfe ){
				}
				usersession.addUser(admin, userdata, false);
				log.debug("created user");
			} catch (RemoteException re) {
				re.printStackTrace();
				userExists = true;
			} catch (DuplicateKeyException dke) {
				userExists = true;
			}
			if (userExists) {
				log.info("User testCRLPeriod already exists, resetting status.");
				usersession.setUserStatus(admin,TESTUSERNAME,UserDataConstants.STATUS_NEW);
				log.debug("Reset status to NEW");
			}
			KeyPair keys = genKeys();
			// user that we know exists...
			X509Certificate cert = (X509Certificate)signsession.createCertificate(admin, TESTUSERNAME, "foo123", keys.getPublic());
			assertNotNull("Failed to create certificate", cert);
			log.debug("Cert=" + cert.toString());
			// Revoke the user
			storeremote.revokeCertificate(admin, cert, null, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
			// Change CRLPeriod
			cainfo.setCRLPeriod(Integer.MAX_VALUE);
			casession.editCA(admin, cainfo);
			// Create new CRL's
			crlSession.run(admin, cadn);
			//Verify that status is not archived
			CertificateInfo certinfo = storeremote.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
			assertFalse("Non Expired Revoked Certificate was archived",certinfo.getStatus() == CertificateDataBean.CERT_ARCHIVED);
		} finally {
			// Restore CRL Period
			cainfo.setCRLPeriod(tempCRLPeriod);
			casession.editCA(admin, cainfo); 
			// Delete and revoke User
			usersession.revokeAndDeleteUser(admin, TESTUSERNAME, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
			// Delete end entity profile
			try{
				storeremote.removeCertificateProfile(admin, TESTPROFILE);
			} catch (RemoteException e )
			{
				log.error("Could not remove Certificate Profile");
			}
				// Delete certificate profile
			try {
				rasession.removeEndEntityProfile(admin, TESTPROFILE);
			} catch (Exception e ) {
				log.error("Could not remove End Entity Profile");
			}
		}
	}

    /**
     * Tests the extension CRL Distribution Point on CRLs
     *
     * @throws Exception error
     */
    public void test06CRLDistPointOnCRL() throws Exception {
        log.debug(">test06CRLDistPointOnCRL()");

        final String cdpURL = "http://www.ejbca.org/foo/bar.crl";
        X509CAInfo cainfo = (X509CAInfo) casession.getCAInfo(admin, caid);
        X509CRL x509crl;
        byte [] cdpDER;

        cainfo.setUseCrlDistributionPointOnCrl(true);
        cainfo.setDefaultCRLDistPoint(cdpURL);
        casession.editCA(admin, cainfo);
        crlSession.run(admin, cadn);
        x509crl = CertTools.getCRLfromByteArray(storeremote.getLastCRL(admin, cadn, false));
        cdpDER = x509crl.getExtensionValue(X509Extensions.CRLDistributionPoints.getId());
        assertNotNull("CRL has no distribution points", cdpDER);

        ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(cdpDER));
        ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
        aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
        CRLDistPoint cdp = new CRLDistPoint((ASN1Sequence) aIn.readObject());
        DistributionPoint[] distpoints = cdp.getDistributionPoints();

        assertEquals("More CRL distributions points than expected", 1, distpoints.length);
        assertEquals("CRL distribution point is different",
                     cdpURL,
                     ((DERIA5String) ((GeneralNames) distpoints[0].getDistributionPoint().getName()).getNames()[0].getName()).getString());

        cainfo.setUseCrlDistributionPointOnCrl(false);
        cainfo.setDefaultCRLDistPoint("");
        casession.editCA(admin, cainfo);
        crlSession.run(admin, cadn);
        x509crl =
            CertTools.getCRLfromByteArray(storeremote.getLastCRL(admin, cadn, false));
        assertNull("CRL has distribution points",
                   x509crl.getExtensionValue(X509Extensions.CRLDistributionPoints.getId()));

        log.debug("<test06CRLDistPointOnCRL()");
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
