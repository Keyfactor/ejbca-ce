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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
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
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.CertConfirmContent;
import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.ErrorMsgContent;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIFreeText;
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
import com.novosec.pkix.asn1.crmf.PBMParameter;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * This test requires RA mode and responseProtection=pbe
 * @author tomas
 *
 */
public class CrmfRAPbeRequestTest extends TestCase {
	
    private static Logger log = Logger.getLogger(CrmfRAPbeRequestTest.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceCmp = "publicweb/cmp";

    private static final int PORT_NUMBER = 5587;
    private static final String CMP_HOST = "127.0.0.1";
    
    private static String userDN = "CN=tomas1,UID=tomas2,O=PrimeKey Solutions AB,C=SE";
    private static String issuerDN = "CN=AdminCA1,O=EJBCA Sample,C=SE";
    private KeyPair keys = null;  

    private static IUserAdminSessionRemote usersession;
    private static int caid = 0;
    private static Admin admin;
    private static X509Certificate cacert = null;

	public CrmfRAPbeRequestTest(String arg0) throws NamingException, RemoteException, CreateException, CertificateEncodingException, CertificateException {
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

	public void test02CrmfHttpOkUser() throws Exception {

		// Create a new good user
		createCmpUser();

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(nonce, transid);
        PKIMessage req = protectPKIMessage(one, false);

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
		checkCmpResponseGeneral(resp, userDN, nonce, transid, false, true);
		checkCmpCertRepMessage(resp, reqId);
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(nonce, transid, hash, reqId);
		assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(req1);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpHttp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, userDN, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(resp);
	}
	
	public void test02CrmfTcpOkUser() throws Exception {

		// Create a new good user
		createCmpUser();

		byte[] nonce = CmpMessageHelper.createSenderNonce();
		byte[] transid = CmpMessageHelper.createSenderNonce();
		
        PKIMessage one = genCertReq(nonce, transid);
        PKIMessage req = protectPKIMessage(one, false);

        int reqId = req.getBody().getIr().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue();
		assertNotNull(req);
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DEROutputStream out = new DEROutputStream(bao);
		out.writeObject(req);
		byte[] ba = bao.toByteArray();
		// Send request and receive response
		byte[] resp = sendCmpTcp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, userDN, nonce, transid, false, true);
		checkCmpCertRepMessage(resp, reqId);
		
		// Send a confirm message to the CA
		String hash = "foo123";
        PKIMessage confirm = genCertConfirm(nonce, transid, hash, reqId);
		assertNotNull(confirm);
        PKIMessage req1 = protectPKIMessage(confirm, false);
		bao = new ByteArrayOutputStream();
		out = new DEROutputStream(bao);
		out.writeObject(req1);
		ba = bao.toByteArray();
		// Send request and receive response
		resp = sendCmpTcp(ba);
		assertNotNull(resp);
		assertTrue(resp.length > 0);
		checkCmpResponseGeneral(resp, userDN, nonce, transid, false, true);
		checkCmpPKIConfirmMessage(resp);
	}
	
	private PKIMessage genCertReq(byte[] nonce, byte[] transid) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		OptionalValidity myOptionalValidity = new OptionalValidity();
		myOptionalValidity.setNotBefore( new org.bouncycastle.asn1.x509.Time( new DERGeneralizedTime("20030211002120Z") ) );
		myOptionalValidity.setNotAfter( new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20061029152120Z")) );
		
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
					new DERInteger(2),
					new GeneralName(new X509Name(userDN)),
					new GeneralName(new X509Name(cacert.getSubjectDN().getName())));
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

	private PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		// Create the PasswordBased protection of the message
		PKIHeader head = msg.getHeader();
		head.setSenderKID(new DEROctetString("primekey".getBytes()));
		// SHA1
		AlgorithmIdentifier owfAlg = new AlgorithmIdentifier("1.3.14.3.2.26");
		// 567 iterations
		int iterationCount = 567;
		DERInteger iteration = new DERInteger(iterationCount);
		// HMAC/SHA1
		AlgorithmIdentifier macAlg = new AlgorithmIdentifier("1.2.840.113549.2.7");
		byte[] salt = "foo123".getBytes();
		DEROctetString derSalt = new DEROctetString(salt);
		
		// Create the new protected return message
		String objectId = "1.2.840.113533.7.66.13";
		if (badObjectId) {
			objectId += ".7";
		}
		PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
		AlgorithmIdentifier pAlg = new AlgorithmIdentifier(new DERObjectIdentifier(objectId), pp);
		head.setProtectionAlg(pAlg);
		PKIBody body = msg.getBody();
		PKIMessage ret = new PKIMessage(head, body);

		// Calculate the protection bits
		byte[] raSecret = "password".getBytes();
		byte[] basekey = new byte[raSecret.length + salt.length];
		for (int i = 0; i < raSecret.length; i++) {
			basekey[i] = raSecret[i];
		}
		for (int i = 0; i < salt.length; i++) {
			basekey[raSecret.length+i] = salt[i];
		}
		// Construct the base key according to rfc4210, section 5.1.3.1
		MessageDigest dig = MessageDigest.getInstance(owfAlg.getObjectId().getId(), "BC");
		for (int i = 0; i < iterationCount; i++) {
			basekey = dig.digest(basekey);
			dig.reset();
		}
		// For HMAC/SHA1 there is another oid, that is not known in BC, but the result is the same so...
		String macOid = macAlg.getObjectId().getId();
		byte[] protectedBytes = ret.getProtectedBytes();
		Mac mac = Mac.getInstance(macOid, "BC");
		SecretKey key = new SecretKeySpec(basekey, macOid);
		mac.init(key);
		mac.reset();
		mac.update(protectedBytes, 0, protectedBytes.length);
		byte[] out = mac.doFinal();
		DERBitString bs = new DERBitString(out);

		// Finally store the protection bytes in the msg
		ret.setProtection(bs);
		return ret;
	}
	
	private PKIMessage genCertConfirm(byte[] nonce, byte[] transid, String hash, int certReqId) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
				
		PKIHeader myPKIHeader =
			new PKIHeader(
					new DERInteger(2),
					new GeneralName(new X509Name(userDN)),
					new GeneralName(new X509Name(cacert.getSubjectDN().getName())));
		myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        // senderNonce
		myPKIHeader.setSenderNonce(new DEROctetString(nonce));
		// TransactionId
		myPKIHeader.setTransactionID(new DEROctetString(transid));
		
		CertConfirmContent cc = new CertConfirmContent(new DEROctetString(hash.getBytes()), new DERInteger(certReqId));
		PKIBody myPKIBody = new PKIBody(cc, 24); // Cert Confirm
		PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);	
		return myPKIMessage;
	}

	private byte[] sendCmpHttp(byte[] message) throws IOException, NoSuchProviderException {
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
	
	private byte[] sendCmpTcp(byte[] message) throws IOException, NoSuchProviderException {
		byte[] respBytes = null;
		try {
			int port = PORT_NUMBER;
			String host = CMP_HOST;
			Socket socket = new Socket(host, port);

			byte[] msg = createTcpMessage(message);

			BufferedOutputStream os = new BufferedOutputStream(socket.getOutputStream());
			os.write(msg);
			os.flush();

			DataInputStream dis = new DataInputStream(socket.getInputStream());
			// Read the length, 32 bits
			int len = dis.readInt();
			System.out.println("Got a message claiming to be of length: " + len);
			// Read the version, 8 bits. Version should be 10 (protocol draft nr 5)
			int ver = dis.readByte();
			System.out.println("Got a message with version: " + ver);
			assertEquals(10, ver);
			
			// Read flags, 8 bits for version 10
			byte flags = dis.readByte();
			System.out.println("Got a message with flags (1 means close): " + flags);
			// Check if the client wants us to close the connection (LSB is 1 in that case according to spec)
			
			// Read message type, 8 bits
			int msgType = dis.readByte();
			System.out.println("Got a message of type: " +msgType);
			
			// Read message
			ByteArrayOutputStream baos = new ByteArrayOutputStream(3072);
			while (dis.available() > 0) {
				baos.write(dis.read());
			}
			System.out.println("Read "+baos.size()+" bytes");
			respBytes = baos.toByteArray();
		} catch(Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
        assertNotNull("Response can not be null.", respBytes);
        assertTrue(respBytes.length > 0);
        return respBytes;
    }

	private byte[] createTcpMessage(byte[] msg) throws IOException {
		ByteArrayOutputStream bao = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(bao); 
		// 0 is pkiReq
		int msgType = 0;
		int len = msg.length;
		// return msg length = msg.length + 3; 1 byte version, 1 byte flags and 1 byte message type
		dos.writeInt(len+3);
		dos.writeByte(10);
		dos.writeByte(0); // 1 if we should close, 0 otherwise
		dos.writeByte(msgType); 
		dos.write(msg);
		dos.flush();
		return bao.toByteArray();
	}
	
    private void checkCmpResponseGeneral(byte[] retMsg, String userDN, byte[] senderNonce, byte[] transId, boolean signed, boolean pbe) throws Exception {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		
    	// The signer, i.e. the CA, check it's the right CA
		PKIHeader header = respObject.getHeader();

    	// Check that the message is signed with the correct digest alg
		if (signed) {
			AlgorithmIdentifier algId = header.getProtectionAlg();
			assertEquals(algId.getObjectId().getId(), PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());			
		}
		if (pbe) {
			AlgorithmIdentifier algId = header.getProtectionAlg();
			assertEquals(algId.getObjectId().getId(), CMPObjectIdentifiers.passwordBasedMac.getId());						
		}

    	// Check that the signer is the expected CA
		assertEquals(header.getSender().getTagNo(), 4);
		X509Name name = X509Name.getInstance(header.getSender().getName()); 
		assertEquals(name.toString(), issuerDN);

		if (signed) {
	    	// Verify the signature
			byte[] protBytes = respObject.getProtectedBytes();
			DERBitString bs = respObject.getProtection();
		    Signature sig;
			try {
				sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
			    sig.initVerify(cacert);
			    sig.update(protBytes);
			    boolean ret = sig.verify(bs.getBytes());
			    assertTrue(ret);
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
		}
		if (pbe) {
			DEROctetString os = header.getSenderKID();
			assertNotNull(os);
				String keyId = new String(os.getOctets());
				log.debug("Found a sender keyId: "+keyId);
				// Verify the PasswordBased protection of the message
				byte[] protectedBytes = respObject.getProtectedBytes();
				DERBitString protection = respObject.getProtection();
				AlgorithmIdentifier pAlg = header.getProtectionAlg();
				log.debug("Protection type is: "+pAlg.getObjectId().getId());
				PBMParameter pp = PBMParameter.getInstance(pAlg.getParameters());
				int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
				log.debug("Iteration count is: "+iterationCount);
				AlgorithmIdentifier owfAlg = pp.getOwf();
				// Normal OWF alg is 1.3.14.3.2.26 - SHA1
				log.debug("Owf type is: "+owfAlg.getObjectId().getId());
				AlgorithmIdentifier macAlg = pp.getMac();
				// Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
				log.debug("Mac type is: "+macAlg.getObjectId().getId());
				byte[] salt = pp.getSalt().getOctets();
				//log.info("Salt is: "+new String(salt));
				String raAuthenticationSecret = "password";
				byte[] raSecret = raAuthenticationSecret.getBytes();
				byte[] basekey = new byte[raSecret.length + salt.length];
				for (int i = 0; i < raSecret.length; i++) {
					basekey[i] = raSecret[i];
				}
				for (int i = 0; i < salt.length; i++) {
					basekey[raSecret.length+i] = salt[i];
				}
				// Construct the base key according to rfc4210, section 5.1.3.1
				MessageDigest dig = MessageDigest.getInstance(owfAlg.getObjectId().getId(), "BC");
				for (int i = 0; i < iterationCount; i++) {
					basekey = dig.digest(basekey);
					dig.reset();
				}
				// HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7 
				String macOid = macAlg.getObjectId().getId();
				Mac mac = Mac.getInstance(macOid, "BC");
				SecretKey key = new SecretKeySpec(basekey, macOid);
				mac.init(key);
				mac.reset();
				mac.update(protectedBytes, 0, protectedBytes.length);
				byte[] out = mac.doFinal();
				// My out should now be the same as the protection bits
				byte[] pb = protection.getBytes();
				boolean ret = Arrays.equals(out, pb);
				assertTrue(ret);
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
		System.out.println("notAfter="+struct.getEndDate().getDate().toString());
    }

    private void checkCmpPKIConfirmMessage(byte[] retMsg) throws IOException {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		PKIHeader header = respObject.getHeader();
		assertEquals(header.getSender().getTagNo(), 4);
		X509Name name = X509Name.getInstance(header.getSender().getName()); 
		assertEquals(name.toString(), cacert.getSubjectDN().getName());
		name = X509Name.getInstance(header.getRecipient().getName()); 
		assertEquals(name.toString(), userDN);

		PKIBody body = respObject.getBody();
		int tag = body.getTagNo();
		assertEquals(tag, 19);
		DERNull n = body.getConf();
		assertNotNull(n);
    }

    private void checkCmpPKIErrorMessage(byte[] retMsg, String sender, String recipient, int errorCode, String errorMsg) throws IOException {
        //
        // Parse response message
        //
		PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		PKIHeader header = respObject.getHeader();
		assertEquals(header.getSender().getTagNo(), 4);
		X509Name name = X509Name.getInstance(header.getSender().getName()); 
		assertEquals(name.toString(), sender);
		name = X509Name.getInstance(header.getRecipient().getName()); 
		assertEquals(name.toString(), recipient);

		PKIBody body = respObject.getBody();
		int tag = body.getTagNo();
		assertEquals(tag, 23);
		ErrorMsgContent n = body.getError();
		assertNotNull(n);
		PKIStatusInfo info = n.getPKIStatus();
		assertNotNull(info);
		DERInteger i = info.getStatus();
		assertEquals(i.getValue().intValue(), 2);
		DERBitString b = info.getFailInfo();
		assertEquals(errorCode, b.intValue());
		if (errorMsg != null) {
			PKIFreeText freeText = info.getStatusString();
			DERUTF8String utf = freeText.getString(0);
			assertEquals(errorMsg, utf.getString());
		}
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
