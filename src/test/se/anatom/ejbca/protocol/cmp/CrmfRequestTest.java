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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;
import javax.ejb.FinderException;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.ErrorMsgContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

public class CrmfRequestTest extends TestCase {
	
    private static Logger log = Logger.getLogger(CrmfRequestTest.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceCmp = "publicweb/apply/cmp";

    private static String userDN = "CN=tomas1, UID=tomas2, O=PrimeKey Solutions AB, C=SE";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static IUserAdminSessionRemote usersession;
    private static int caid = 0;
    private static Admin admin;
    private static X509Certificate cacert = null;

	public CrmfRequestTest(String arg0) throws NamingException, RemoteException, CreateException, CertificateEncodingException, CertificateException {
		super(arg0);
        admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
		CertTools.installBCProvider();
		Context ctx = getInitialContext();
        Object obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer) iter.next()).intValue();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        CAInfo cainfo = casession.getCAInfo(admin, caid);
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
        obj = ctx.lookup("UserAdminSession");
        IUserAdminSessionHome userhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        usersession = userhome.create();
        
        issuerDN = cacert.getIssuerDN().getName();
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
			keys = KeyTools.genKeys(1024);
		}
	}
	
	protected void tearDown() throws Exception {
		super.tearDown();
	}
	
	public void test01CrmfHttpUnknowUser() throws Exception {
        // A name that does not exis
	    userDN = "CN=abc123rry5774466, O=PrimeKey Solutions AB, C=SE";

		byte[] nonce = new byte[16];
        SecureRandom randomSource = SecureRandom.getInstance("SHA1PRNG");
        randomSource.nextBytes(nonce);
		byte[] transid = new byte[16];
        randomSource.nextBytes(transid);
		
        PKIMessage req = genCertReq(nonce, transid);
		assertNotNull(req);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte ba[] = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, userDN, nonce, transid);
		checkCmpFailMessage(resp, "User not found: abc123rry5774466");
	}
	
	public void test02CrmfHttpOkUser() throws Exception {

		// Create a new good user
		createCmpUser();

		byte[] nonce = new byte[16];
        SecureRandom randomSource = SecureRandom.getInstance("SHA1PRNG");
        randomSource.nextBytes(nonce);
		byte[] transid = new byte[16];
        randomSource.nextBytes(transid);
		
        PKIMessage req = genCertReq(nonce, transid);
        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		assertNotNull(req);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte ba[] = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, userDN, nonce, transid);
		checkCmpCertRepMessage(resp, reqId);
	}

	private PKIMessage genCertReq(byte[] nonce, byte[] transid) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		OptionalValidity myOptionalValidity = new OptionalValidity();
		myOptionalValidity.setNotBefore( new org.bouncycastle.asn1.x509.Time( new DERGeneralizedTime("20030211002120Z") ) );
		myOptionalValidity.setNotAfter( new org.bouncycastle.asn1.x509.Time(new Date()) );
		
		CertTemplate myCertTemplate = new CertTemplate();
		myCertTemplate.setValidity( myOptionalValidity );
		myCertTemplate.setIssuer(new X509Name(issuerDN));
		myCertTemplate.setSubject(new X509Name(userDN));
		byte[]                  bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
		myCertTemplate.setPublicKey(keyInfo);
		
		CertRequest myCertRequest = new CertRequest(new DERInteger(4), myCertTemplate);
		//myCertRequest.addControls(new AttributeTypeAndValue(CRMFObjectIdentifiers.regInfo_utf8Pairs, new DERInteger(12345)));
		
		// POPO
		/*
		PKMACValue myPKMACValue =
			new PKMACValue(
					new AlgorithmIdentifier(new DERObjectIdentifier("8.2.1.2.3.4"), new DERBitString(new byte[] { 8, 1, 1, 2 })),
					new DERBitString(new byte[] { 12, 29, 37, 43 }));
		
		POPOPrivKey myPOPOPrivKey = new POPOPrivKey(new DERBitString(new byte[] { 44 }), 2); //take choice pos tag 2
		
		POPOSigningKeyInput myPOPOSigningKeyInput =
			new POPOSigningKeyInput(
					myPKMACValue,
					new SubjectPublicKeyInfo(
							new AlgorithmIdentifier(new DERObjectIdentifier("9.3.3.9.2.2"), new DERBitString(new byte[] { 2, 9, 7, 3 })),
							new byte[] { 7, 7, 7, 4, 5, 6, 7, 7, 7 }));
		POPOSigningKey myPOPOSigningKey =
			new POPOSigningKey(
					new AlgorithmIdentifier(new DERObjectIdentifier("1.3.3.3.3.1"), new DERBitString(new byte[] { 2, 0, 0, 3 })),
					new DERBitString(new byte[] { 99, 88, 77, 66, 55, 44, 33, 22, 11 }));
		myPOPOSigningKey.setPoposkInput( myPOPOSigningKeyInput );
		
		ProofOfPossession myProofOfPossession = new ProofOfPossession(myPOPOPrivKey, 2);
		*/
		// raVerified POPO (meaning there is no POPO)
		ProofOfPossession myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
		
		CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest);
		myCertReqMsg.setPop(myProofOfPossession);
		//myCertReqMsg.addRegInfo(new AttributeTypeAndValue(new DERObjectIdentifier("1.3.6.2.2.2.2.3.1"), new DERInteger(1122334455)));
		AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123")); 
		myCertReqMsg.addRegInfo(av);
		
		CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
		//myCertReqMessages.addCertReqMsg(myCertReqMsg);
				
		PKIHeader myPKIHeader =
			new PKIHeader(
					new DERInteger(1),
					new GeneralName(new X509Name("C=DE, O=NOVOSEC AG, OU=Security Division, E=sender@novosec.com")),
					new GeneralName(new X509Name("C=DE, O=NOVOSEC AG, OU=Security Division, E=recipient@novosec.com")));
		myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
		myPKIHeader.setSenderNonce(new DEROctetString(nonce));
		// TransactionId
		myPKIHeader.setTransactionID(new DEROctetString(transid));
		//myPKIHeader.setRecipNonce(new DEROctetString(new String("RecipNonce").getBytes()));
		//PKIFreeText myPKIFreeText = new PKIFreeText(new DERUTF8String("hello"));
		//myPKIFreeText.addString(new DERUTF8String("free text string"));
		//myPKIHeader.setFreeText(myPKIFreeText);
		
		PKIBody myPKIBody = new PKIBody(myCertReqMessages, 0); // initialization request
		PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);	
		return myPKIMessage;
	}

    private byte[] sendCmp(byte[] message) throws IOException, NoSuchProviderException {
        // POST the CMP request
        // we are going to do a POST
    	String resource = resourceCmp;
    	String urlString = httpReqPath + '/' + resource;
    	log.debug("UrlString =" + urlString);
        HttpURLConnection con = null;
        URL url = new URL(urlString);
        con = (HttpURLConnection)url.openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-type", "application/pkixcmp");
        con.connect();
        // POST it
        OutputStream os = con.getOutputStream();
        os.write(message);
        os.close();

        assertEquals("Response code", 200, con.getResponseCode());
        assertEquals("Content-Type", "application/pkixcmp", con.getContentType());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // This works for small requests, and CMP requests are small enough
        InputStream in = con.getInputStream();
        int b = in.read();
        while (b != -1) {
            baos.write(b);
            b = in.read();
        }
        baos.flush();
        in.close();
        byte[] respBytes = baos.toByteArray();
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        return respBytes;
    }

    private void checkCmpResponseGeneral(byte[] retMsg, String userDN, byte[] senderNonce, byte[] transId) throws IOException {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		
		System.out.println(respObject);
		System.out.println(ASN1Dump.dumpAsString(respObject));

    	// The signer, i.e. the CA, check it's the right CA
		PKIHeader header = respObject.getHeader();

    	// Check that the message is signed with the correct digest alg
		AlgorithmIdentifier algId = header.getProtectionAlg();
		assertEquals(algId.getObjectId().getId(), PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());

    	// Check that the signer is the expected CA
		assertEquals(header.getSender().getTagNo(), 4);
		X509Name name = X509Name.getInstance(header.getSender().getName()); 
		assertEquals(name.toString(), issuerDN);

    	// Verify the signature
		byte[] protBytes = respObject.getProtectedBytes();
		DERBitString bs = respObject.getProtection();
	    Signature sig;
		try {
			sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
		    sig.initVerify(cacert);
		    sig.update(protBytes);
		    sig.verify(bs.getBytes());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			assertTrue(false);
		} catch (SignatureException e) {
			e.printStackTrace();
			assertTrue(false);
		}

    	// --SenderNonce
        // SenderNonce is something the server came up with, but it should be 16 chars
		byte[] nonce = header.getSenderNonce().getOctets();
		assertEquals(nonce.length, 16);

    	// --Recipient Nonce
        // recipient nonce should be the same as we sent away as sender nonce
		nonce = header.getRecipNonce().getOctets();
		assertEquals(new String(nonce), new String(senderNonce));

    	// --Transaction ID
        // transid should be the same as the one we sent
		nonce = header.getTransactionID().getOctets();
		assertEquals(new String(nonce), new String(transId));
        

    	// --Fail info
        // No failInfo on this success message

    	// --Message type
        // --Success status

        //
        // Check different message types
        //
                // We got a reply with a requested certificate 
                // Issued certificate must be first
                    // check the returned certificate
                        // issued certificate
                        // ca certificate
        
    }
    
    private void checkCmpFailMessage(byte[] retMsg, String failMsg) throws IOException {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		
		PKIBody body = respObject.getBody();
		int tag = body.getTagNo();
		assertEquals(tag, 23);
		ErrorMsgContent c = body.getError();
		assertNotNull(c);
		PKIStatusInfo info = c.getPKIStatus();
		assertNotNull(info);
		assertEquals(2, info.getStatus().getValue().intValue());
		int i = info.getFailInfo().intValue();
		assertEquals(i,1<<7); // bit nr 7 (INCORRECT_DATA) set is 128
		assertEquals(failMsg, info.getStatusString().getString(0).getString());
    }
    private void checkCmpCertRepMessage(byte[] retMsg, int requestId) throws IOException {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		
		PKIBody body = respObject.getBody();
		int tag = body.getTagNo();
		assertEquals(tag, 1);
		CertRepMessage c = body.getIp();
		assertNotNull(c);
		CertResponse resp = c.getResponse(0);
		assertNotNull(resp);
		assertEquals(resp.getCertReqId().getValue().intValue(), requestId); 
		PKIStatusInfo info = resp.getStatus();
		assertNotNull(info);
		assertEquals(0, info.getStatus().getValue().intValue());
		CertifiedKeyPair kp = resp.getCertifiedKeyPair();
		assertNotNull(kp);
		CertOrEncCert cc = kp.getCertOrEncCert();
		assertNotNull(cc);
		X509CertificateStructure struct = cc.getCertificate();
		assertNotNull(struct);
		assertEquals(CertTools.stringToBCDNString(struct.getSubject().toString()), CertTools.stringToBCDNString(userDN));
		assertEquals(CertTools.stringToBCDNString(struct.getIssuer().toString()), CertTools.stringToBCDNString(cacert.getSubjectDN().getName()));
    }

    //
    // Private helper methods
    //
    private void createCmpUser() throws RemoteException, AuthorizationDeniedException, FinderException, UserDoesntFullfillEndEntityProfile, ApprovalException, WaitingForApprovalException {
        // Make user that we know...
        boolean userExists = false;
		userDN = "C=SE,O=PrimeKey,CN=cmptest";
        try {
            usersession.addUser(admin,"cmptest","foo123",userDN,null,"cmptest@primekey.se",false,SecConst.EMPTY_ENDENTITYPROFILE,SecConst.CERTPROFILE_FIXED_ENDUSER,SecConst.USER_ENDUSER,SecConst.TOKEN_SOFT_PEM,0,caid);
            log.debug("created user: cmptest, foo123, "+userDN);
        } catch (RemoteException re) {
            if (re.detail instanceof DuplicateKeyException) {
                userExists = true;
            }
        } catch (DuplicateKeyException dke) {
            userExists = true;
        }

        if (userExists) {
            log.debug("User cmptest already exists.");
            usersession.setUserStatus(admin,"cmptest",UserDataConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
        
    }

}
