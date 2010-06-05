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

package org.ejbca.core.ejb.ra;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Random;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.NonEjbTestTools;
import org.ejbca.util.TestTools;

/**
 * Test the combined function for editing and requesting a keystore/certificate
 * in a single transaction.
 * 
 * Note that the rollback tests requires a transactional database, if using MySQL this means InnoDB and not MyISAM.
 *   
 * @version $Id$
 */
public class CertificateRequestSessionTest extends TestCase {

	private static final Logger log = Logger.getLogger(CertificateRequestSessionTest.class);
	private final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

	public void test000Setup() {
		TestTools.createTestCA();
	}
	
	/**
	 * Verify that a soft token can be generated in a single transaction.
	 */
	public void testSoftTokenRequestRollback() throws Exception {
		// First try a successful request and validate the returned KeyStore
		String username = "softTokenRequestTest-" + new Random().nextInt();
		String password = "foo123";
		UserDataVO userdata = new UserDataVO(username, "CN="+username, TestTools.getTestCAId(), null, null, SecConst.USER_ENDUSER,
				SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_JKS, 0, null);
		userdata.setPassword(password);
		byte[] encodedKeyStore = TestTools.getCertificateRequestSession().processSoftTokenReq(admin, userdata, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA, true);
        // Convert encoded KeyStore to the proper return type
        java.security.KeyStore keyStore = java.security.KeyStore.getInstance("JKS");
        keyStore.load(new ByteArrayInputStream(encodedKeyStore), userdata.getPassword().toCharArray());
        assertNotNull(keyStore);
        Enumeration<String> aliases = keyStore.aliases();
        String alias = aliases.nextElement();
        Certificate cert = keyStore.getCertificate(alias);
        if (CertTools.isSelfSigned(cert)) {
        	// Ignore the CA cert and get another one
        	alias = aliases.nextElement();
            cert = keyStore.getCertificate(alias);
        }
        assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
        		CertTools.getSubjectDN(cert), userdata.getDN());
    	keyStore.getKey(alias, password.toCharArray());
    	// Try again with a user that does not exist and use values that we will break certificate generation
    	// If the transaction really is rolled back successfully there will be no trace of the user in the database
    	// We can do this by relying on the Unique Subject DN constraint
		String username2 = "softTokenRequestTest-" + new Random().nextInt();
    	userdata.setUsername(username2);	// Still the same Subject DN
		userdata.setPassword(password);
		assertFalse(username2+" already exists.", TestTools.getUserAdminSession().existsUser(admin, username2));
		try {
			TestTools.getCertificateRequestSession().processSoftTokenReq(admin, userdata, null, "1024", AlgorithmConstants.KEYALGORITHM_RSA, true);
			fail("Certificate creation did not fail as expected.");
		} catch (Exception e) {
			log.debug("Got an exception as expected: " + e.getMessage());
		}
		assertFalse("Failed keystore generation request never rolled back created user '"+username2+"'.", TestTools.getUserAdminSession().existsUser(admin, username2));
	}

	/**
	 * Verify that a soft token can be generated in a single transaction.
	 */
	public void testCertificateRequestRollback() throws Exception {
		// First try a successful request and validate the returned KeyStore
		String username = "certificateRequestTest-" + new Random().nextInt();
		String password = "foo123";
		UserDataVO userdata = new UserDataVO(username, "CN="+username, TestTools.getTestCAId(), null, null, SecConst.USER_ENDUSER,
				SecConst.EMPTY_ENDENTITYPROFILE, SecConst.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
		userdata.setPassword(password);
		String pkcs10 = new String(Base64.encode(NonEjbTestTools.generatePKCS10Req("CN=Ignored", password)));
		byte[] encodedCertificate = TestTools.getCertificateRequestSession().processCertReq(admin, userdata, pkcs10, SecConst.CERT_REQ_TYPE_PKCS10, null, SecConst.CERT_RES_TYPE_CERTIFICATE);
        Certificate cert = CertTools.getCertfromByteArray(encodedCertificate);
        assertEquals("CertTools.getSubjectDN: " + CertTools.getSubjectDN(cert) + " userdata.getDN:" + userdata.getDN(),
        		CertTools.getSubjectDN(cert), userdata.getDN());
    	// Try again with a user that does not exist and use values that we will break certificate generation
    	// If the transaction really is rolled back successfully there will be no trace of the user in the database
    	// We can do this by relying on the Unique Public Key constraint
		String username2 = "certificateRequestTest-" + new Random().nextInt();
    	userdata.setUsername(username2);	// Still the same Subject DN
		userdata.setPassword(password);
		try {
			TestTools.getCertificateRequestSession().processCertReq(admin, userdata, pkcs10, SecConst.CERT_REQ_TYPE_PKCS10, null, SecConst.CERT_RES_TYPE_CERTIFICATE);
			fail("Certificate creation did not fail as expected.");
		} catch (Exception e) {
			log.debug("Got an exception as expected: " + e.getMessage());
		}
		assertFalse("Failed certificate generation request never rolled back user created '"+username2+"'.", TestTools.getUserAdminSession().existsUser(admin, username2));
	}

	public void testZZZTearDown() {
		TestTools.removeTestCA();
	}

}
