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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;

import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Helper class to create different standard parts of CMP messages
 * 
 * @author tomas
 * @version $Id: CmpMessageHelper.java,v 1.3 2006-09-21 15:34:31 anatom Exp $
 */
public class CmpMessageHelper {
	private static Logger log = Logger.getLogger(CmpMessageHelper.class);

	public static PKIHeader createPKIHeader(X509Name sender, X509Name recipient, String senderNonce, String recipientNonce, String transactionId) {
		PKIHeader myPKIHeader =
			new PKIHeader(
					new DERInteger(2),
					new GeneralName(sender),
					new GeneralName(recipient));
		myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
		if (senderNonce != null) {
			myPKIHeader.setSenderNonce(new DEROctetString(Base64.decode(senderNonce.getBytes())));					
		}
		if (recipientNonce != null) {
			myPKIHeader.setRecipNonce(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
		}
		if (transactionId != null) {
			myPKIHeader.setTransactionID(new DEROctetString(Base64.decode(transactionId.getBytes())));
		}
		return myPKIHeader;
	}

    public static byte[] signPKIMessage(PKIMessage myPKIMessage, X509Certificate signCert, PrivateKey signKey, String digestAlg, String provider) throws InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException, IOException, CertificateEncodingException {
		X509CertificateStructure signStruct = X509CertificateStructure.getInstance(new ASN1InputStream(new ByteArrayInputStream(signCert.getEncoded())).readObject());
		CmpMessageHelper.buildCertBasedPKIProtection( myPKIMessage, signStruct, signKey, digestAlg, provider);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DEROutputStream mout = new DEROutputStream( baos );
		mout.writeObject( myPKIMessage );
		mout.close();
		return baos.toByteArray();
    }
    
	public static void buildCertBasedPKIProtection( PKIMessage pKIMessage, X509CertificateStructure cert, PrivateKey key, String digestAlg, String provider )
	throws NoSuchProviderException, NoSuchAlgorithmException, SecurityException, SignatureException, InvalidKeyException
	{
		// SHA1WITHRSA
		DERObjectIdentifier oid = PKCSObjectIdentifiers.sha1WithRSAEncryption;
		if (digestAlg.equals(CMSSignedGenerator.DIGEST_SHA256)) {
			oid = PKCSObjectIdentifiers.sha256WithRSAEncryption;			
		}
		if (digestAlg.equals(CMSSignedGenerator.DIGEST_MD5)) {
			oid = PKCSObjectIdentifiers.md5WithRSAEncryption;			
		}
		pKIMessage.getHeader().setProtectionAlg( new AlgorithmIdentifier(oid) );
		
		Signature sig = Signature.getInstance( pKIMessage.getHeader().getProtectionAlg().getObjectId().getId(), provider );
		sig.initSign(key);
		sig.update( pKIMessage.getProtectedBytes() );
		
		pKIMessage.setProtection( new DERBitString(sig.sign()) );
		pKIMessage.addExtraCert( cert );
	}

	/** Creates a 16 bytes random sender nonce
	 * 
	 * @return byte array of length 16
	 */
	public static byte[] createSenderNonce() {
    	// Sendernonce is a random number
    	byte[] senderNonce = new byte[16];
        Random randomSource;
        randomSource = new Random();
        randomSource.nextBytes(senderNonce);
    	return senderNonce;
	}
	/**
	 * creates a very simple error message in response to msg (that's why we switch sender and recipient)
	 * @param msg
	 * @param status
	 * @param failInfo
	 * @param failText
	 * @return IResponseMessage that can be sent to user
	 */
	public static IResponseMessage createUnprotectedErrorMessage(BaseCmpMessage msg, ResponseStatus status, FailInfo failInfo, String failText) {
		// Create a failure message
		CmpErrorResponseMessage resp = new CmpErrorResponseMessage();
		resp.setRecipientNonce(msg.getSenderNonce());
		resp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
		resp.setSender(msg.getRecipient());
		resp.setRecipient(msg.getSender());
		resp.setTransactionId(msg.getTransactionId());
		resp.setFailInfo(failInfo);
		resp.setStatus( status);
		resp.setFailText(failText);
		try {
			resp.create();
		} catch (InvalidKeyException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (NoSuchAlgorithmException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (NoSuchProviderException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (SignRequestException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (NotFoundException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (IOException e) {
			log.error("Exception during CMP processing: ", e);			
		}
		return resp;
	}
}
