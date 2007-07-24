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
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * This test requires:
 * mode=ra, responseProtection=pbe, authenticationsecret=password, allowraverifypopo=true,namegenerationscheme=DN
 * Allow CN, O, C in DN and rfc822Name, UPN in altNames in the end entity profile configured in cmp.properties
 * 
 * You need a CMP tcp listener configured on port 5547.
 *
 * endentityprofile=KeyId, certificateprofile=KeyId, caname=ProfileDefault
 * 
 * Two CAs: AdminCA1 with DN "CN=AdminCA1,O=EJBCA Sample,C=SE"
 *          AdminCA2 with DN "CN=AdminCA1,O=EJBCA Sample2,C=SE"
 *          
 * There must be two end entity profiles and two certificate profiles with names KeyId1 and KeyId2.
 * 
 * Cert Profile with name KeyId1 must have key usage "digital signature", non-overridable
 * Cert Profile with name KeyId2 must have key usage "non repudiation", non-overridable
 * EE Profile with name KeyId1 must have a fixed, non-modifiable C=SE, an O, a CN and be using certProfile KeyId1
 * EE Profile with name KeyId1 must have default CA with name AdminCA1
 * EE Profile with name KeyId2 must have a fixed, non-modifiable C=NO, an O, a CN  and be using certProfile KeyId2
 * EE Profile with name KeyId2 must have default CA with name AdminCA2 
 * 
 * @author tomas
 * @version $Id: CrmfRAPbeMultipleKeyIdRequestTest.java,v 1.1 2007-07-24 10:51:41 anatom Exp $
 */
public class CrmfRAPbeMultipleKeyIdRequestTest extends CmpTestCase {
	
    private static Logger log = Logger.getLogger(CrmfRAPbeMultipleKeyIdRequestTest.class);

    private static final String PBEPASSWORD = "password";
    
    private static String userDN1 = "C=SE,O=PrimeKey,CN=cmptestKeyId1";
    private static String userDN2 = "C=NO,O=PrimeKey,CN=cmptestKeyId2";
    private static String issuerDN1 = null;
    private static String issuerDN2 = null;
    private KeyPair keys = null;  

    private static IUserAdminSessionRemote usersession;
	private ICertificateStoreSessionRemote storesession = null;
    private static int caid1 = 0;
    private static int caid2 = 0;
    private static Admin admin;
    private static X509Certificate cacert1 = null;
    private static X509Certificate cacert2 = null;

	public CrmfRAPbeMultipleKeyIdRequestTest(String arg0) throws NamingException, RemoteException, CreateException, CertificateEncodingException, CertificateException {
		super(arg0);
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
		CertTools.installBCProvider();
		Context ctx = getInitialContext();
        Object obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        // Try to get caIds
        CAInfo adminca1 = casession.getCAInfo(admin, "AdminCA1");
        caid1 = adminca1.getCAId();
        CAInfo adminca2 = casession.getCAInfo(admin, "AdminCA2");
        caid2 = adminca2.getCAId();
        if ( (caid1 == 0) || (caid2 == 0) ) {
        	assertTrue("No active CA! Must have AdminCA1 and AdminCA2 to run tests!", false);
        }        	
        CAInfo cainfo = casession.getCAInfo(admin, caid1);
        Collection certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                cacert1 = CertTools.getCertfromByteArray(cert.getEncoded());            	
            }
        } else {
            log.error("NO CACERT for AdminCA1: " + caid1);
        }
        cainfo = casession.getCAInfo(admin, caid2);
        certs = cainfo.getCertificateChain();
        if (certs.size() > 0) {
            Iterator certiter = certs.iterator();
            X509Certificate cert = (X509Certificate) certiter.next();
            String subject = CertTools.getSubjectDN(cert);
            if (StringUtils.equals(subject, cainfo.getSubjectDN())) {
                // Make sure we have a BC certificate
                cacert2 = CertTools.getCertfromByteArray(cert.getEncoded());            	
            }
        } else {
            log.error("NO CACERT for AdminCA2: " + caid2);
        }
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class);
        usersession = userhome.create();
		ICertificateStoreSessionHome storeHome = (ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class);
		this.storesession = storeHome.create();
        
        issuerDN1 = cacert1.getIssuerDN().getName();
        issuerDN2 = cacert2.getIssuerDN().getName();
	}
	
    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");
        return ctx;
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
	
	public void test01CrmfHttpOkUserWrongKeyId() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
		// A message with the KeyId "foobarfoobar" should not be known by this
        PKIMessage one = genCertReq(issuerDN1, userDN1, keys, cacert1, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "foobarfoobar");

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
		checkCmpFailMessage(resp, "End entity profile with name 'foobarfoobar' not found.", 23, reqId, 2); // We'll get back a FailInfo.BAD_REQUEST
	}

	public void test02CrmfHttpOkUserKeyId1() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN1, userDN1, keys, cacert1, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId1");

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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN1, cacert1, resp, reqId);
		String altNames = CertTools.getSubjectAlternativeName(cert);
		assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
		assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
		
		// Check key usage that it is digitalSignature for KeyId1 and nonRepudiation for KeyId2
		boolean[] ku = cert.getKeyUsage();
		assertTrue(ku[0]);
		assertFalse(ku[1]);
		assertFalse(ku[2]);
		assertFalse(ku[3]);
		assertFalse(ku[4]);
		assertFalse(ku[5]);
		assertFalse(ku[6]);
		assertFalse(ku[7]);
		assertFalse(ku[8]);
		// Check DN that must be SE for KeyId1
		assertEquals("SE", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN1, cacert1, nonce, transid, hash, reqId);
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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN1, cacert1, resp);
		
		// Now revoke the bastard!
		PKIMessage rev = genRevReq(issuerDN1, userDN1, cert.getSerialNumber(), cacert1, nonce, transid);
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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN1, userDN1, cert.getSerialNumber(), cacert1, resp, true);
		int reason = checkRevokeStatus(issuerDN1, cert.getSerialNumber());
		assertEquals(reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);
		
		// Create a revocation request for a non existing cert, chould fail!
		rev = genRevReq(issuerDN1, userDN1, new BigInteger("1"), cacert1, nonce, transid);
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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN1, userDN1, cert.getSerialNumber(), cacert1, resp, false);

	}


	public void test03CrmfTcpOkUserKeyId1() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN1, userDN1, keys, cacert1, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId1");

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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN1, cacert1, resp, reqId);
		String altNames = CertTools.getSubjectAlternativeName(cert);
		assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
		assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
		
		// Check key usage that it is digitalSignature for KeyId1 and nonRepudiation for KeyId2
		boolean[] ku = cert.getKeyUsage();
		assertTrue(ku[0]);
		assertFalse(ku[1]);
		assertFalse(ku[2]);
		assertFalse(ku[3]);
		assertFalse(ku[4]);
		assertFalse(ku[5]);
		assertFalse(ku[6]);
		assertFalse(ku[7]);
		assertFalse(ku[8]);
		// Check DN that must be SE for KeyId1
		assertEquals("SE", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN1, cacert1, nonce, transid, hash, reqId);
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
		checkCmpResponseGeneral(resp, issuerDN1, userDN1, cacert1, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN1, cacert1, resp);
	}
	
	public void test04CrmfTcpOkUserKeyId2() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN2, userDN2, keys, cacert2, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId2");

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
		checkCmpResponseGeneral(resp, issuerDN2, userDN2, cacert2, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN2, cacert2, resp, reqId);
		String altNames = CertTools.getSubjectAlternativeName(cert);
		assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
		assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
		
		// Check key usage that it is digitalSignature for KeyId1 and nonRepudiation for KeyId2
		boolean[] ku = cert.getKeyUsage();
		assertFalse(ku[0]);
		assertTrue(ku[1]);
		assertFalse(ku[2]);
		assertFalse(ku[3]);
		assertFalse(ku[4]);
		assertFalse(ku[5]);
		assertFalse(ku[6]);
		assertFalse(ku[7]);
		assertFalse(ku[8]);
		// Check DN that must be SE for KeyId1 and NO for KeyId2
		assertEquals("NO", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN2, cacert2, nonce, transid, hash, reqId);
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
		checkCmpResponseGeneral(resp, issuerDN2, userDN2, cacert2, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN2, cacert2, resp);
	}
	
	public void test05CrmfHttpOkUserKeyId2() throws Exception {

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(issuerDN2, userDN2, keys, cacert2, nonce, transid, true);
        PKIMessage req = protectPKIMessage(one, false, PBEPASSWORD, "KeyId2");

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
		checkCmpResponseGeneral(resp, issuerDN2, userDN2, cacert2, nonce, transid, false, true);
		X509Certificate cert = checkCmpCertRepMessage(userDN2, cacert2, resp, reqId);
		String altNames = CertTools.getSubjectAlternativeName(cert);
		assertTrue(altNames.indexOf("upn=fooupn@bar.com") != -1);
		assertTrue(altNames.indexOf("rfc822name=fooemail@bar.com") != -1);
		
		// Check key usage that it is digitalSignature for KeyId1 and nonRepudiation for KeyId2
		boolean[] ku = cert.getKeyUsage();
		assertFalse(ku[0]);
		assertTrue(ku[1]);
		assertFalse(ku[2]);
		assertFalse(ku[3]);
		assertFalse(ku[4]);
		assertFalse(ku[5]);
		assertFalse(ku[6]);
		assertFalse(ku[7]);
		assertFalse(ku[8]);
		// Check DN that must be SE for KeyId1 and NO for KeyId2
		assertEquals("NO", CertTools.getPartFromDN(cert.getSubjectDN().getName(), "C"));
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(userDN2, cacert2, nonce, transid, hash, reqId);
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
		checkCmpResponseGeneral(resp, issuerDN2, userDN2, cacert2, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(userDN2, cacert2, resp);
		
		// Now revoke the bastard!
		PKIMessage rev = genRevReq(issuerDN2, userDN2, cert.getSerialNumber(), cacert2, nonce, transid);
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
		checkCmpResponseGeneral(resp, issuerDN2, userDN2, cacert2, nonce, transid, false, true);
		checkCmpRevokeConfirmMessage(issuerDN2, userDN2, cert.getSerialNumber(), cacert2, resp, true);
		int reason = checkRevokeStatus(issuerDN2, cert.getSerialNumber());
		assertEquals(reason, RevokedCertInfo.REVOKATION_REASON_KEYCOMPROMISE);		
	}

	
	public void test99CleanUp() throws Exception {
		String user1 = CertTools.getPartFromDN(userDN1, "CN");
		String user2 = CertTools.getPartFromDN(userDN2, "CN");
		try {
			usersession.deleteUser(admin, user1);
			usersession.deleteUser(admin, user2);			
		} catch (Exception e) {
			// Ignore errors
		}
	}
	

    //
    // Private helper methods
    //

    private int checkRevokeStatus(String issuerDN, BigInteger serno) throws RemoteException {
    	int ret = RevokedCertInfo.NOT_REVOKED;
    	RevokedCertInfo info = storesession.isRevoked(admin, issuerDN, serno);
    	ret = info.getReason();
    	return ret;
    }

}
