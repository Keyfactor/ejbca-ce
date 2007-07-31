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

package se.anatom.ejbca.protocol.cmp;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.approvalrequests.TestRevocationApproval;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.ui.cli.batch.BatchMakeP12;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * This test requires:
 * mode=ra, responseProtection=pbe, authenticationsecret=password, allowraverifypopo=true.
 * Allow CN, O, C in DN and rfc822Name, UPN in altNames in the end entity profile configured in cmp.properties
 * 
 * You need a CMP tcp listener configured on port 5547.
 * 
 * @author tomas
 * @version $Id: CrmfRAPbeRequestTest.java,v 1.12 2007-07-31 13:31:37 jeklund Exp $
 */
public class CrmfRAPbeRequestTest extends CmpTestCase {
	
    private static Logger log = Logger.getLogger(CrmfRAPbeRequestTest.class);

    // This must be the same password as in cmp.properties if PBE is used.
    private static final String PBEPASSWORD = "password";
    private static final String APPROVINGADMINNAME = "superadmin";
    
    private static String userDN = "C=SE,O=PrimeKey,CN=cmptest";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static IUserAdminSessionRemote userAdminSession = null;
    private static ICertificateStoreSessionRemote certificateStoreSession = null;
    private static ICAAdminSessionRemote caAdminSession = null;
    private static IApprovalSessionRemote approvalSession = null;
    private static int caid = 0;
    private static Admin admin;
    private static X509Certificate cacert = null;

	public CrmfRAPbeRequestTest(String arg0) throws NamingException, RemoteException, CreateException,
			CertificateEncodingException, CertificateException {
		super(arg0);
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
		CertTools.installBCProvider();
        Context ctx = new javax.naming.InitialContext();
		caAdminSession = ((ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(
				ctx.lookup(ICAAdminSessionHome.JNDI_NAME), ICAAdminSessionHome.class)).create();
		userAdminSession = ((IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(
				ctx.lookup(IUserAdminSessionHome.JNDI_NAME), IUserAdminSessionHome.class)).create();
		certificateStoreSession = ((ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(
				ctx.lookup(ICertificateStoreSessionHome.JNDI_NAME), ICertificateStoreSessionHome.class)).create();
		approvalSession = ((IApprovalSessionHome) javax.rmi.PortableRemoteObject.narrow(
				ctx.lookup(IApprovalSessionHome.JNDI_NAME), IApprovalSessionHome.class)).create();
        // Try to use AdminCA1 if it exists
        CAInfo adminca1 = caAdminSession.getCAInfo(admin, "AdminCA1");
        if (adminca1 == null) {
            Collection caids = caAdminSession.getAvailableCAs(admin);
            Iterator iter = caids.iterator();
            while (iter.hasNext()) {
            	caid = ((Integer) iter.next()).intValue();
            }        	
        } else {
        	caid = adminca1.getCAId();
        }
        if (caid == 0) {
        	assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }        	
        CAInfo cainfo = caAdminSession.getCAInfo(admin, caid);
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                cacert = CertTools.getCertfromByteArray(cert.getEncoded());            	
            }
        } else {
            log.error("NO CACERT for caid " + caid);
        }
        
        issuerDN = cacert.getIssuerDN().getName();
	}
	
	protected void setUp() throws Exception {
		super.setUp();
		if (keys == null) {
			keys = KeyTools.genKeys("512", CATokenConstants.KEYALGORITHM_RSA);
		}
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void test01CrmfHttpOkUser() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		assertNotNull(req);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte[] ba = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmpHttp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN, cacert, resp, reqId);
		String altNames = CertTools.getSubjectAlternativeName(cert);
		assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
		assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
		assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(req1);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpHttp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN, cacert, resp);
		
		// Now revoke the bastard!
		PKIMessage rev = genRevReq(issuerDN, userDN, cert.getSerialNumber(), cacert, nonce, transid);
        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD);
		assertNotNull(revReq);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(revReq);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpHttp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, true);
		int reason = checkRevokeStatus(issuerDN, cert.getSerialNumber());
		assertEquals(reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
		// Create a revocation request for a non existing cert, chould fail!
		rev = genRevReq(issuerDN, userDN, new BigInteger("1"), cacert, nonce, transid);
        revReq = protectPKIMessage(rev, false, PBEPASSWORD);
		assertNotNull(revReq);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(revReq);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpHttp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN, userDN, cert.getSerialNumber(), cacert, resp, false);

	}
	
	
	public void test02CrmfTcpOkUser() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN, userDN, keys, cacert, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		assertNotNull(req);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte[] ba = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmpTcp(ba, 5);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpCertRepMessage(userDN, cacert, resp, reqId);
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN, cacert, nonce, transid, hash, reqId);
		assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false, PBEPASSWORD);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(req1);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpTcp(ba, 5);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, issuerDN, userDN, cacert, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN, cacert, resp);
	}
	
	
	public void test99CleanUp() throws Exception {
		userAdminSession.deleteUser(admin, "cmptest");
	}
	
	public void testRevocationApprovals() throws Exception {
	    // Generate random username and CA name
		String randomPostfix = Integer.toString((new Random(new Date().getTime() + 4711)).nextInt(999999));
		String caname = "cmpRevocationCA" + randomPostfix;
		String username = "cmpRevocationUser" + randomPostfix;
		X509CAInfo cainfo = null;
	    try {
			// Generate CA with approvals for revocation enabled
	    	int caID = TestRevocationApproval.createApprovalCA(admin, caname, CAInfo.REQ_APPROVAL_REVOCATION, caAdminSession);
			// Get CA cert
			cainfo = (X509CAInfo) caAdminSession.getCAInfo(admin, caID);
	        assertNotNull(cainfo);
			X509Certificate newCACert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
			// Create a user and generate the cert
			UserDataVO userdata = new UserDataVO(username,"CN="+username,cainfo.getCAId(),null,null,1,SecConst.EMPTY_ENDENTITYPROFILE,
					SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.TOKEN_SOFT_P12,0,null);
			userdata.setPassword("foo123");
			userAdminSession.addUser(admin, userdata , true);
		    BatchMakeP12 makep12 = new BatchMakeP12();
		    File tmpfile = File.createTempFile("ejbca", "p12");
		    makep12.setMainStoreDir(tmpfile.getParent());
		    makep12.createAllNew();
		    Collection userCerts = certificateStoreSession.findCertificatesByUsername(admin, username);
		    assertTrue( userCerts.size() == 1 );
		    X509Certificate cert = (X509Certificate) userCerts.iterator().next();
		    // revoke via CMP and verify response
			byte[] nonce = CmpMessageHelper.createSenderNonce();
			byte[] transid = CmpMessageHelper.createSenderNonce();
			ByteArrayOutputStream bao = new ByteArrayOutputStream();
			DEROutputStream out = new DEROutputStream(bao);
			PKIMessage rev = genRevReq(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, nonce, transid);
	        PKIMessage revReq = protectPKIMessage(rev, false, PBEPASSWORD);
			assertNotNull(revReq);
			bao = new ByteArrayOutputStream();
			out = new DEROutputStream(bao);
			out.writeObject(revReq);
			byte[] ba = bao.toByteArray();
			byte[] resp = sendCmpHttp(ba);
			assertNotNull(resp);
			assertTrue(resp.length > 0);
			checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, true);
			checkCmpRevokeConfirmMessage(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, resp, true);
			int reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
			assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
			// try to revoke one more via CMP and verify error
			nonce = CmpMessageHelper.createSenderNonce();
			transid = CmpMessageHelper.createSenderNonce();
			bao = new ByteArrayOutputStream();
			out = new DEROutputStream(bao);
			rev = genRevReq(cainfo.getSubjectDN(), userdata.getDN(), cert.getSerialNumber(), newCACert, nonce, transid);
	        revReq = protectPKIMessage(rev, false, PBEPASSWORD);
			assertNotNull(revReq);
			bao = new ByteArrayOutputStream();
			out = new DEROutputStream(bao);
			out.writeObject(revReq);
			ba = bao.toByteArray();
			resp = sendCmpHttp(ba);
			assertNotNull(resp);
			assertTrue(resp.length > 0);
			checkCmpResponseGeneral(resp, cainfo.getSubjectDN(), userdata.getDN(), newCACert, nonce, transid, false, true);
			checkCmpFailMessage(resp, "The request is already awaiting approval.", CmpPKIBodyConstants.REVOCATIONRESPONSE, 0,
					ResponseStatus.FAILURE.getIntValue());
			reason = checkRevokeStatus(cainfo.getSubjectDN(), cert.getSerialNumber());
			assertEquals(reason, RevokedCertInfo.NOT_REVOKED);
			// Approve revocation and verify success
			Admin approvingAdmin = new Admin((X509Certificate) certificateStoreSession.findCertificatesByUsername(
					admin, APPROVINGADMINNAME).iterator().next());
			TestRevocationApproval.approveRevocation(admin, approvingAdmin, username, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE,
					ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE, certificateStoreSession, approvalSession);
	    } finally {
			// Delete user
			userAdminSession.deleteUser(admin, username);
			// Nuke CA
	        try {
	        	caAdminSession.revokeCA(admin, cainfo.getCAId(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED);
	        } finally {
	        	caAdminSession.removeCA(admin, cainfo.getCAId());
	        }
	    }
	} // testRevocationApprovals

    //
    // Private helper methods
    //
	
    private int checkRevokeStatus(String issuerDN, BigInteger serno) throws RemoteException {
    	int ret = RevokedCertInfo.NOT_REVOKED;
    	RevokedCertInfo info = certificateStoreSession.isRevoked(admin, issuerDN, serno);
    	ret = info.getReason();
    	return ret;
    }

    static byte[] bluexir = Base64.decode(("MIICIjCB1AIBAqQCMACkVjBUMQswCQYDVQQGEwJOTDEbMBkGA1UEChMSQS5FLlQu"+
		"IEV1cm9wZSBCLlYuMRQwEgYDVQQLEwtEZXZlbG9wbWVudDESMBAGA1UEAxMJVGVz"+
		"dCBDQSAxoT4wPAYJKoZIhvZ9B0INMC8EEAK/H7Do+55N724Kdvxm7NcwCQYFKw4D"+
		"AhoFAAICA+gwDAYIKwYBBQUIAQIFAKILBAlzc2xjbGllbnSkEgQQpFpBsonfhnW8"+
		"ia1otGchraUSBBAyzd3nkKAzcJqGFrDw0jkYoIIBLjCCASowggEmMIIBIAIBADCC"+
		"ARmkJqARGA8yMDA2MDkxOTE2MTEyNlqhERgPMjAwOTA2MTUxNjExMjZapR0wGzEZ"+
		"MBcGA1UEAwwQU29tZSBDb21tb24gTmFtZaaBoDANBgkqhkiG9w0BAQEFAAOBjgAw"+
		"gYoCgYEAuBgTGPgXrS3AIPN6iXO6LNf5GzAcb/WZhvebXMdxdrMo9+5hw/Le5St/"+
		"Sz4J93rxU95b2LMuHTg8U6njxC2lZarNExZTdEwnI37X6ep7lq1purq80zD9bFXj"+
		"ougRD5MHfhDUAQC+btOgEXkanoAo8St3cbtHoYUacAXN2Zs/RVcCBAABAAGpLTAr"+
		"BgNVHREEJDAioCAGCisGAQQBgjcUAgOgEgwQdXBuQGFldGV1cm9wZS5ubIAAoBcD"+
		"FQAy/vSoNUevcdUxXkCQx3fvxkjh6A==").getBytes());

}
