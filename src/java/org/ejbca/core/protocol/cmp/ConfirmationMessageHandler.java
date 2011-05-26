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

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.Base64;

/**
 * Message handler for certificate request confirmation message.
 * 
 * According to RFC 4210 4.2.2.2:
 *  "Where verification of the cert confirmation message fails, the RA/CA
 *   MUST revoke the newly issued certificate if it has been published or
 *   otherwise made available."
 * 
 * However, EJBCA does not keep track of the transaction and always responds
 * with a ResponseStatus.SUCCESS Certificate Confirmation ACK.
 * 
 * @author tomas
 * @version $Id$
 */
public class ConfirmationMessageHandler extends BaseCmpMessageHandler implements ICmpMessageHandler {
	
	private static final Logger LOG = Logger.getLogger(ConfirmationMessageHandler.class);
	private static final InternalResources INTRES = InternalResources.getInstance();
	
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	
	public ConfirmationMessageHandler(Admin admin, CAAdminSession caAdminSession, EndEntityProfileSession endEntityProfileSession, CertificateProfileSession certificateProfileSession) {
		super(admin, caAdminSession, endEntityProfileSession, certificateProfileSession);
		raAuthenticationSecret = CmpConfiguration.getRAAuthenticationSecret();
		responseProtection = CmpConfiguration.getResponseProtection();
	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		LOG.trace(">handleMessage");
		int version = msg.getHeader().getPvno().getValue().intValue();
		IResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		if (version > 1) {
			// Try to find a HMAC/SHA1 protection key
			String owfAlg = null;
			String macAlg = null;
			int iterationCount = 1024;
			String cmpRaAuthSecret = null;	
			String keyId = getSenderKeyId(msg.getHeader());
			if (keyId != null) {
				try {
					CmpPbeVerifyer verifyer = new CmpPbeVerifyer(msg.getMessage());
					owfAlg = verifyer.getOwfOid();
					macAlg = verifyer.getMacOid();
					iterationCount = verifyer.getIterationCount();
					// If we use a globally configured shared secret for all CAs we check it right away
					if (raAuthenticationSecret != null) {
						if (!verifyer.verify(raAuthenticationSecret)) {
							String err = "Protection verified false on ConformationMessage";
							LOG.error(err);
							return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, err);
						}
						cmpRaAuthSecret = raAuthenticationSecret;
					} else {
						// Get the correct profiles' and CA ids based on current configuration. 
						CAInfo caInfo;
						try {
							int eeProfileId = getUsedEndEntityProfileId(keyId);
							int caId = getUsedCaId(keyId, eeProfileId);
							caInfo = caAdminSession.getCAInfo(admin, caId);
						} catch (NotFoundException e) {
							LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
							return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
						} catch (EJBException e) {
							final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
							LOG.error(errMsg, e);			
							return null;	// Fatal error
						}
						if (caInfo instanceof X509CAInfo) {
							cmpRaAuthSecret = ((X509CAInfo) caInfo).getCmpRaAuthSecret();
						}
						// Now we know which CA the request is for, if we didn't use a global shared secret we can check it now!
						if (cmpRaAuthSecret == null || !verifyer.verify(cmpRaAuthSecret)) {
							String errMsg = INTRES.getLocalizedMessage("cmp.errorauthmessage");
							LOG.info(errMsg); // info because this is something we should expect and we handle it
							if (verifyer.getErrMsg() != null) {
								errMsg = verifyer.getErrMsg();
							}
							return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
						}
					}
				} catch (NoSuchAlgorithmException e) {
					LOG.error("Exception calculating protection: ", e);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				} catch (NoSuchProviderException e) {
					LOG.error("Exception calculating protection: ", e);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				} catch (InvalidKeyException e) {
					LOG.error("Exception calculating protection: ", e);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, e.getMessage());
				}
			}
			LOG.debug("Creating a PKI confirm message response");
			CmpConfirmResponseMessage cresp = new CmpConfirmResponseMessage();
			cresp.setRecipientNonce(msg.getSenderNonce());
			cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
			cresp.setSender(msg.getRecipient());
			cresp.setRecipient(msg.getSender());
			cresp.setTransactionId(msg.getTransactionId());
			// Set all protection parameters
			LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
			if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
				cresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
			}
			resp = cresp;
			try {
				resp.create();
			} catch (InvalidKeyException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchAlgorithmException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NoSuchProviderException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (SignRequestException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (NotFoundException e) {
				LOG.error("Exception during CMP processing: ", e);			
			} catch (IOException e) {
				LOG.error("Exception during CMP processing: ", e);			
			}							
		} else {
			LOG.debug("Cmp1999 - Not creating a PKI confirm meessage response");
		}
		return resp;
	}
}
