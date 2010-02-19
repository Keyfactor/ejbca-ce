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

package org.ejbca.core.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.TestTools;
import org.ejbca.util.keystore.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * @author tomas
 * @version $Id$
 */
public class CrmfRARequestTest extends CmpTestCase {

	private static Logger log = Logger.getLogger(CrmfRARequestTest.class);

	private static final String PBEPASSWORD = "password";

	private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";

	private static int caid = 0;
	private static Admin admin;
	private static X509Certificate cacert = null;

	public CrmfRARequestTest(String arg0) throws RemoteException, CertificateEncodingException, CertificateException {
		super(arg0);
		admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
		CryptoProviderTools.installBCProvider();
		// Try to use AdminCA1 if it exists
		CAInfo adminca1 = TestTools.getCAAdminSession().getCAInfo(admin, "AdminCA1");
		if (adminca1 == null) {
			Collection<Integer> caids = TestTools.getCAAdminSession().getAvailableCAs(admin);
			Iterator<Integer> iter = caids.iterator();
			while (iter.hasNext()) {
				caid = iter.next().intValue();
			}
		} else {
			caid = adminca1.getCAId();
		}
		if (caid == 0) {
			assertTrue("No active CA! Must have at least one active CA to run tests!", false);
		}
		CAInfo cainfo = TestTools.getCAAdminSession().getCAInfo(admin, caid);
		Collection<X509Certificate> certs = cainfo.getCertificateChain();
		if (certs.size() > 0) {
			Iterator<X509Certificate> certiter = certs.iterator();
			X509Certificate cert = certiter.next();
			String subject = CertTools.getSubjectDN(cert);
			if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
				// Make sure we have a BC certificate
				cacert = (X509Certificate)CertTools.getCertfromByteArray(cert.getEncoded());				
			}
		} else {
			log.error("NO CACERT for caid " + caid);
		}
		issuerDN = cacert.getIssuerDN().getName();
		// Configure CMP for this test
		TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_OPERATIONMODE, "ra");
		TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO, "true");
		TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RESPONSEPROTECTION, "signature");
		TestTools.getConfigurationSession().updateProperty(CmpConfiguration.CONFIG_RA_AUTHENTICATIONSECRET, "password");
	}

	public void crmfHttpUserTest(String userDN, KeyPair keys, String sExceptionMessage) throws Exception {

		// Create a new good user

		final byte[] nonce = CmpMessageHelper.createSenderNonce();
		final byte[] transid = CmpMessageHelper.createSenderNonce();
		final int reqId;
		{
			final PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true, null, null, null);
			final PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, 567);

			reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
			assertNotNull(req);
			final ByteArrayOutputStream bao = new ByteArrayOutputStream();
			final DEROutputStream out = new DEROutputStream(bao);
			out.writeObject(req);
			final byte[] ba = bao.toByteArray();
			// Send request and receive response
			final byte[] resp = sendCmpHttp(ba);
			assertNotNull(resp);
			assertTrue(resp.length > 0);
			checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, sExceptionMessage==null, false);
			if ( sExceptionMessage==null ) {
				checkCmpCertRepMessage(userDN, cacert, resp, reqId);
			} else {
				checkCmpFailMessage(resp, sExceptionMessage,
									CmpPKIBodyConstants.ERRORMESSAGE, reqId, FailInfo.BAD_REQUEST.hashCode());
			}
		}{
			// Send a confirm message to the CA
			final String hash = "foo123";
			final PKIMessage con = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
			assertNotNull(con);
			PKIMessage confirm = protectPKIMessage(con, false, PBEPASSWORD, 567);
			final ByteArrayOutputStream bao = new ByteArrayOutputStream();
			final DEROutputStream out = new DEROutputStream(bao);
			out.writeObject(confirm);
			final byte[] ba = bao.toByteArray();
			// Send request and receive response
			final byte[] resp = sendCmpHttp(ba);
			assertNotNull(resp);
			assertTrue(resp.length > 0);
			checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, false);
			checkCmpPKIConfirmMessage(userDN, cacert, resp);
		}
	}
	public void test01CrmfHttpOkUser() throws Exception {
		final KeyPair key = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
		final String userDN1 = "C=SE,O=PrimeKey,CN=cmptest1";
		final String userDN2 = "C=SE,O=PrimeKey,CN=cmptest2";
		final String userName1 = "cmptest1";
		final String userName2 = "cmptest2";
		createCmpUser(userName1, userDN1);
		crmfHttpUserTest(userDN1, key, null);
		crmfHttpUserTest(userDN1, key, null);
		createCmpUser(userName2, userDN2);
		crmfHttpUserTest(userDN2, key, InternalResources.getInstance().getLocalizedMessage("signsession.key_exists_for_another_user", "'"+userName2+"'", "'"+userName1+"'"));
	}
	
	public void testZZZCleanUp() throws Exception {
		TestTools.getConfigurationSession().restoreConfiguration();
	}

	//
	// Private helper methods
	//
	private void createCmpUser(String userName, String userDN) throws RemoteException, AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException {
		// Make user that we know...
		try {
			TestTools.getUserAdminSession().addUser(admin, userName,"foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
			log.debug("created user: "+userName+", foo123, "+userDN);
		} catch (Exception e) {
			log.debug("User "+userName+" already exists.");
			TestTools.getUserAdminSession().setUserStatus(admin, userName, UserDataConstants.STATUS_NEW);
			log.debug("Reset status to NEW");
		}
	}
}
