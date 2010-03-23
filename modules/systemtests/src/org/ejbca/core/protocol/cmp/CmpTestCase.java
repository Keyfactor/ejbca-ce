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

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Hashtable;
import java.util.Vector;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

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
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.CertTools;

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
import com.novosec.pkix.asn1.cmp.RevDetails;
import com.novosec.pkix.asn1.cmp.RevRepContent;
import com.novosec.pkix.asn1.cmp.RevReqContent;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.PBMParameter;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * Helper class for CMP Junit tests
 * @author tomas
 * @version $Id$
 *
 */
public class CmpTestCase extends TestCase {

    private static final Logger log = Logger.getLogger(CmpTestCase.class);
    
    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceCmp = "publicweb/cmp";

    private static final int PORT_NUMBER = 5587;
    private static final String CMP_HOST = "127.0.0.1";
    
	public CmpTestCase(String arg0) {
		super(arg0);
	}

	protected PKIMessage genCertReq(String issuerDN, String userDN, KeyPair keys, X509Certificate cacert, byte[] nonce, byte[] transid, boolean raVerifiedPopo, X509Extensions extensions, Date notBefore, Date notAfter) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
		return genCertReq(issuerDN, userDN, "UPN=fooupn@bar.com,rfc822Name=fooemail@bar.com", keys, cacert, nonce, transid, raVerifiedPopo, extensions, notBefore, notAfter);
	}
	
	protected PKIMessage genCertReq(String issuerDN, String userDN, String altNames, KeyPair keys, X509Certificate cacert, byte[] nonce, byte[] transid, boolean raVerifiedPopo, X509Extensions extensions, Date notBefore, Date notAfter) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
		OptionalValidity myOptionalValidity = new OptionalValidity();
		org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
		if (notBefore != null) {
			nb = new org.bouncycastle.asn1.x509.Time(notBefore);
		}
		org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date()); 
		if (notAfter != null) {
			na = new org.bouncycastle.asn1.x509.Time(notAfter);
		}
		myOptionalValidity.setNotBefore(nb);
		myOptionalValidity.setNotAfter(na);
		
		CertTemplate myCertTemplate = new CertTemplate();
		myCertTemplate.setValidity( myOptionalValidity );
		myCertTemplate.setIssuer(new X509Name(issuerDN));
		myCertTemplate.setSubject(new X509Name(userDN));
		byte[]                  bytes = keys.getPublic().getEncoded();
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
        ASN1InputStream         dIn = new ASN1InputStream(bIn);
        SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
		myCertTemplate.setPublicKey(keyInfo);
		// If we did not pass any extensions as parameter, we will create some of our own, standard ones
        X509Extensions exts = extensions;
        if (exts == null) {
        	// SubjectAltName
    		// Some altNames
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            DEROutputStream         dOut = new DEROutputStream(bOut);
            Vector values = new Vector();
            Vector oids = new Vector();
        	if (altNames != null) {
                GeneralNames san = CertTools.getGeneralNamesFromAltName(altNames);
                dOut.writeObject(san);
                byte[] value = bOut.toByteArray();
                X509Extension sanext = new X509Extension(false, new DEROctetString(value));
                values.add(sanext);
                oids.add(X509Extensions.SubjectAlternativeName);
        	}
            // KeyUsage
            int bcku = 0;
            bcku = X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment | X509KeyUsage.nonRepudiation;
            X509KeyUsage ku = new X509KeyUsage(bcku);
            bOut = new ByteArrayOutputStream();
            dOut = new DEROutputStream(bOut);
            dOut.writeObject(ku);
            byte[] value = bOut.toByteArray();
        	X509Extension kuext = new X509Extension(false, new DEROctetString(value));
            values.add(kuext);
            oids.add(X509Extensions.KeyUsage);            

            // Make the complete extension package
            exts = new X509Extensions(oids, values); 
        }
		myCertTemplate.setExtensions(exts);
		
		CertRequest myCertRequest = new CertRequest(new DERInteger(4), myCertTemplate);
		//myCertRequest.addControls(new AttributeTypeAndValue(CRMFObjectIdentifiers.regInfo_utf8Pairs, new DERInteger(12345)));
		CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest);
		
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
		*/
		ProofOfPossession myProofOfPossession = null;
		if (raVerifiedPopo) {
			// raVerified POPO (meaning there is no POPO)
			myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
		} else {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DEROutputStream mout = new DEROutputStream( baos );
			mout.writeObject( myCertRequest );
			mout.close();
			byte[] popoProtectionBytes = baos.toByteArray();
			Signature sig = Signature.getInstance( PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
			sig.initSign(keys.getPrivate());
			sig.update( popoProtectionBytes );
			
			DERBitString bs = new DERBitString(sig.sign());

			POPOSigningKey myPOPOSigningKey =
				new POPOSigningKey(
						new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption),
						bs);
			//myPOPOSigningKey.setPoposkInput( myPOPOSigningKeyInput );
			myProofOfPossession = new ProofOfPossession(myPOPOSigningKey, 1);			
		}
				
		myCertReqMsg.setPop(myProofOfPossession);
		//myCertReqMsg.addRegInfo(new AttributeTypeAndValue(new DERObjectIdentifier("1.3.6.2.2.2.2.3.1"), new DERInteger(1122334455)));
		AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123")); 
		myCertReqMsg.addRegInfo(av);
		
		CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);
		//myCertReqMessages.addCertReqMsg(myCertReqMsg);
				
		//log.debug("CAcert subject name: "+cacert.getSubjectDN().getName());
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

	protected PKIMessage genRevReq(String issuerDN, String userDN, BigInteger serNo, X509Certificate cacert, byte[] nonce, byte[] transid, boolean crlEntryExtension) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {
		CertTemplate myCertTemplate = new CertTemplate();
		myCertTemplate.setIssuer(new X509Name(issuerDN));
		myCertTemplate.setSubject(new X509Name(userDN));
		myCertTemplate.setSerialNumber(new DERInteger(serNo));

		RevDetails myRevDetails = new RevDetails(myCertTemplate);
		ReasonFlags reasonbits = new ReasonFlags(ReasonFlags.keyCompromise);
		myRevDetails.setRevocationReason(reasonbits);
		if (crlEntryExtension) {
			CRLReason crlReason = new CRLReason(CRLReason.cessationOfOperation);
			X509Extension ext = new X509Extension(false, new DEROctetString(crlReason.getEncoded()));
			Hashtable ht = new Hashtable();
			ht.put(X509Extensions.ReasonCode, ext);
			myRevDetails.setCrlEntryDetails(new X509Extensions(ht));
		}
		
		RevReqContent myRevReqContent = new RevReqContent(myRevDetails);
				
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
		
		PKIBody myPKIBody = new PKIBody(myRevReqContent, 11); // revocation request
		PKIMessage myPKIMessage = new PKIMessage(myPKIHeader, myPKIBody);	
		return myPKIMessage;
	}

	protected PKIMessage genCertConfirm(String userDN, X509Certificate cacert, byte[] nonce, byte[] transid, String hash, int certReqId) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		
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

	protected PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, int iterations) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		return protectPKIMessage(msg, badObjectId, password, "primekey", iterations);
	}
	
	protected PKIMessage protectPKIMessage(PKIMessage msg, boolean badObjectId, String password, String keyId, int iterations) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
		// Create the PasswordBased protection of the message
		PKIHeader head = msg.getHeader();
		head.setSenderKID(new DEROctetString(keyId.getBytes()));
		// SHA1
		AlgorithmIdentifier owfAlg = new AlgorithmIdentifier("1.3.14.3.2.26");
		// 567 iterations
		int iterationCount = iterations;
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
		byte[] raSecret = password.getBytes();
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

	protected byte[] sendCmpHttp(byte[] message) throws IOException, NoSuchProviderException {
        // POST the CMP request
        // we are going to do a POST
    	String resource = resourceCmp;
    	String urlString = httpReqPath + '/' + resource;
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

        assertEquals("Unexpected HTTP response code.", 200, con.getResponseCode());
        // Some appserver (Weblogic) responds with "application/pkixcmp; charset=UTF-8"
		assertNotNull("No content type in response.", con.getContentType());
        assertTrue(con.getContentType().startsWith("application/pkixcmp"));
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
        assertNotNull(respBytes);
        assertTrue(respBytes.length > 0);
        return respBytes;
    }

	
	protected void checkCmpResponseGeneral(byte[] retMsg, String issuerDN, String userDN, X509Certificate cacert, byte[] senderNonce, byte[] transId, boolean signed, boolean pbe) throws Exception {
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
			assertNotNull("The AlgorithmIdentifier in the response signature could not be read.", algId);
			assertEquals(algId.getObjectId().getId(), PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());			
		}
		if (pbe) {
			AlgorithmIdentifier algId = header.getProtectionAlg();
			assertNotNull(algId);
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
    
	/**
	 * 
	 * @param message
	 * @param type set to 5 when sending a PKI request, 3 when sending a PKIConf 
	 * @return
	 * @throws IOException
	 * @throws NoSuchProviderException
	 */
	protected byte[] sendCmpTcp(byte[] message, int type) throws IOException, NoSuchProviderException {
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
			log.info("Got a message claiming to be of length: " + len);
			// Read the version, 8 bits. Version should be 10 (protocol draft nr 5)
			int ver = dis.readByte();
			log.info("Got a message with version: " + ver);
			assertEquals(ver, 10);
			
			// Read flags, 8 bits for version 10
			byte flags = dis.readByte();
			log.info("Got a message with flags (1 means close): " + flags);
			// Check if the client wants us to close the connection (LSB is 1 in that case according to spec)
			
			// Read message type, 8 bits
			int msgType = dis.readByte();
			log.info("Got a message of type: " +msgType);
			assertEquals(msgType, type);
			
			// Read message
			ByteArrayOutputStream baos = new ByteArrayOutputStream(3072);
			while (dis.available() > 0) {
				baos.write(dis.read());
			}
			log.info("Read "+baos.size()+" bytes");
			respBytes = baos.toByteArray();
		} catch(ConnectException e) {
			assertTrue("This test requires a CMP TCP listener to be configured on " + CMP_HOST + ":" + PORT_NUMBER + ". Edit conf/cmp.properties and redeploy.", false);
		} catch(EOFException e) {
			assertTrue("Response was malformed.", false);
		} catch(Exception e) {
			e.printStackTrace();
			assertTrue(false);
		}
		assertNotNull(respBytes);
		assertTrue(respBytes.length > 0);
        return respBytes;
    }

    protected X509Certificate checkCmpCertRepMessage(String userDN, X509Certificate cacert, byte[] retMsg, int requestId) throws IOException, CertificateException {
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
		return (X509Certificate)CertTools.getCertfromByteArray(struct.getEncoded());
    }

    protected void checkCmpPKIConfirmMessage(String userDN, X509Certificate cacert, byte[] retMsg) throws IOException {
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

    protected void checkCmpRevokeConfirmMessage(String issuerDN, String userDN, BigInteger serno, X509Certificate cacert, byte[] retMsg, boolean success) throws IOException {
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
		assertEquals(tag, 12);
		RevRepContent n = body.getRp();
		assertNotNull(n);
		PKIStatusInfo info = n.getPKIStatusInfo(0);
		if (success) {
			assertEquals(info.getStatus().getValue().intValue(), 0);
		} else {
			assertEquals(info.getStatus().getValue().intValue(), 2);			
		}
		
    }
    
    /**
     * 
     * @param retMsg
     * @param failMsg expected fail message
     * @param tag 1 is answer to initialisation resp, 3 certification resp etc, 23 is error 
     * @param err a number from FailInfo
     * @throws IOException
     */
    protected void checkCmpFailMessage(byte[] retMsg, String failMsg, int exptag, int requestId, int err) throws IOException {
        //
        // Parse response message
        //
		final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
		assertNotNull(respObject);
		
		final PKIBody body = respObject.getBody();
		final int tag = body.getTagNo();
		assertEquals(exptag, tag);
		final PKIStatusInfo info;
		if (exptag == CmpPKIBodyConstants.ERRORMESSAGE) {
			ErrorMsgContent c = body.getError();
			assertNotNull(c);
			info = c.getPKIStatus();
			assertNotNull(info);
			assertEquals(ResponseStatus.FAILURE.getIntValue(), info.getStatus().getValue().intValue());
			int i = info.getFailInfo().intValue();
			assertEquals(i,1<<err);
		} else if (exptag == CmpPKIBodyConstants.REVOCATIONRESPONSE) {
			RevRepContent rrc = body.getRp();
			assertNotNull(rrc);
			info = rrc.getPKIStatusInfo(0);
			assertNotNull(info);
			assertEquals(ResponseStatus.FAILURE.getIntValue(), info.getStatus().getValue().intValue());
			assertEquals(FailInfo.BAD_REQUEST.getAsBitString(), info.getFailInfo());
		} else {
			CertRepMessage c = null;
			if (exptag == CmpPKIBodyConstants.INITIALIZATIONRESPONSE) {
				c = body.getIp();
			} else if (exptag == CmpPKIBodyConstants.CERTIFICATIONRESPONSE) {
				c = body.getCp();
			}
			assertNotNull(c);
			CertResponse resp = c.getResponse(0);
			assertNotNull(resp);
			assertEquals(resp.getCertReqId().getValue().intValue(), requestId);
			info = resp.getStatus();
			assertNotNull(info);
			assertEquals(ResponseStatus.FAILURE.getIntValue(), info.getStatus().getValue().intValue());
			assertEquals(FailInfo.INCORRECT_DATA.getAsBitString(), info.getFailInfo());
		}
		log.debug("expected fail message: '"+failMsg+"'. received fail message: '"+info.getStatusString().getString(0).getString()+"'.");
		assertEquals(failMsg, info.getStatusString().getString(0).getString());			
    }
    
    protected void checkCmpPKIErrorMessage(byte[] retMsg, String sender, String recipient, int errorCode, String errorMsg) throws IOException {
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
		assertEquals("Return wrong error code.", errorCode, b.intValue());
		if (errorMsg != null) {
			PKIFreeText freeText = info.getStatusString();
			DERUTF8String utf = freeText.getString(0);
			assertEquals(errorMsg, utf.getString());
		}
    }

	//
	// Private methods
	// 
	
	private static byte[] createTcpMessage(byte[] msg) throws IOException {
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
	


}
