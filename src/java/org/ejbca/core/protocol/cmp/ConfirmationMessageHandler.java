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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Properties;

import javax.ejb.CreateException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;

import com.novosec.pkix.asn1.cmp.PKIHeader;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: ConfirmationMessageHandler.java,v 1.4 2006-10-23 12:01:33 anatom Exp $
 */
public class ConfirmationMessageHandler implements ICmpMessageHandler {
	
	private static Logger log = Logger.getLogger(ConfirmationMessageHandler.class);
	
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of prtection for the response message */
	private String responseProtection = null;
	
	public ConfirmationMessageHandler(Properties prop) throws CreateException {
		String str = prop.getProperty("raAuthenticationSecret");
		if (StringUtils.isNotEmpty(str)) {
			log.debug("raAuthenticationSecret is not null");
			raAuthenticationSecret = str;
		}			
		str = prop.getProperty("responseProtection");
		if (StringUtils.isNotEmpty(str)) {
			log.debug("responseProtection="+str);
			responseProtection = str;
		}			

	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		log.debug(">handleMessage");
		int version = msg.getHeader().getPvno().getValue().intValue();
		//IResponseMessage resp = null;
		IResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		if (version > 1) {
			// Try to find a HMAC/SHA1 protection key
			String owfAlg = null;
			String macAlg = null;
			String keyId = null;
			int iterationCount = 1024;
			// Flag to set if protection is verified ok!
			boolean protectionVerified = false;
			PKIHeader head = msg.getHeader();
			DEROctetString os = head.getSenderKID();
			if (os != null) {
				keyId = new String(os.getOctets());
				log.debug("Found a sender keyId: "+keyId);
				try {
					CmpPbeVerifyer verifyer = new CmpPbeVerifyer(raAuthenticationSecret, msg.getMessage());
					protectionVerified = verifyer.verify();
					owfAlg = verifyer.getOwfOid();
					macAlg = verifyer.getMacOid();
					iterationCount = verifyer.getIterationCount();
				} catch (NoSuchAlgorithmException e) {
					log.error("Exception calculating protection: ", e);
					resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				} catch (NoSuchProviderException e) {
					log.error("Exception calculating protection: ", e);
					resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				} catch (InvalidKeyException e) {
					log.error("Exception calculating protection: ", e);
					resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				}
			} else {
				// If we don't have any protection to verify, we simly say that it is verified ok
				protectionVerified = true;
			}
			if (protectionVerified) {
				log.debug("Creating a PKI confirm message response");
				CmpConfirmResponseMessage cresp = new CmpConfirmResponseMessage();
				cresp.setRecipientNonce(msg.getSenderNonce());
				cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
				cresp.setSender(msg.getRecipient());
				cresp.setRecipient(msg.getSender());
				cresp.setTransactionId(msg.getTransactionId());
	    		// Set all protection parameters
				log.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+raAuthenticationSecret);
	    		if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (raAuthenticationSecret != null) ) {
	    			cresp.setPbeParameters(keyId, raAuthenticationSecret, owfAlg, macAlg, iterationCount);
	    		}
	    		resp = cresp;
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
			} else {
				String err = "Protection verified false on ConformationMessage";
				log.error(err);
				resp = CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, err);
			}
		} else {
			log.debug("Cmp1999 - Not creating a PKI confirm meessage response");
		}
		return resp;
	}
	
}
