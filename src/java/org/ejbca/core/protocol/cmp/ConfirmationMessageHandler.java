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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.cmp.authentication.HMACAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.ICMPAuthenticationModule;
import org.ejbca.core.protocol.cmp.authentication.VerifyPKIMessage;

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
	private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
	
//	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
//	private String raAuthenticationSecret = null;
	/** Parameter used to determine the type of protection for the response message */
	private String responseProtection = null;
	/** CA Session used to sign the response */
	private CaSessionLocal caSession;
    /** User Admin Session used to authenticate the request */
    private EndEntityAccessSession endEntityAccessSession;
    /** Certificate Store Session used to authenticate the request */
    private CertificateStoreSession certificateStoreSession;
    /** Access Control Session used to authenticate the request */
    private AccessControlSession authorizationSession;
    /** Authentication Provider Session used to authenticate the request */
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
	
	public ConfirmationMessageHandler(AuthenticationToken admin, CaSessionLocal caSession, EndEntityProfileSession endEntityProfileSession,
            CertificateProfileSession certificateProfileSession, CertificateStoreSession certStoreSession, AccessControlSession authSession,
            EndEntityAccessSession eeAccessSession, WebAuthenticationProviderSessionLocal authProvSession) {

		super(admin, caSession, endEntityProfileSession, certificateProfileSession);
//		raAuthenticationSecret = CmpConfiguration.getRAAuthenticationSecret();
		responseProtection = CmpConfiguration.getResponseProtection();
		this.caSession = caSession;
        this.endEntityAccessSession = eeAccessSession;
        this.certificateStoreSession = certStoreSession;
        this.authorizationSession = authSession;
        this.authenticationProviderSession = authProvSession;
	}
	public ResponseMessage handleMessage(BaseCmpMessage msg) {
		if (LOG.isTraceEnabled()) {
			LOG.trace(">handleMessage");
		}
		int version = msg.getHeader().getPvno().getValue().intValue();
		ResponseMessage resp = null;
		// if version == 1 it is cmp1999 and we should not return a message back
		if (version > 1) {
			// Try to find a HMAC/SHA1 protection key
			String owfAlg = null;
			String macAlg = null;
			int iterationCount = 1024;
			String cmpRaAuthSecret = null;	
			String keyId = getSenderKeyId(msg.getHeader());
			if (keyId != null) {

				CAInfo caInfo;
				try {
					int eeProfileId = getUsedEndEntityProfileId(keyId);
					int caId = getUsedCaId(keyId, eeProfileId);
					caInfo = caSession.getCAInfo(admin, caId);
				} catch (NotFoundException e) {
					LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
				} catch (EJBException e) {
					final String errMsg = INTRES.getLocalizedMessage(CMP_ERRORADDUSER);
					LOG.error(errMsg, e);			
					return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
				} catch (CADoesntExistsException e) {
                    LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
                } catch (AuthorizationDeniedException e) {
                    LOG.info(INTRES.getLocalizedMessage(CMP_ERRORGENERAL, e.getMessage()), e);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.INCORRECT_DATA, e.getMessage());
                }

                //Verify the authenticity of the message
                VerifyPKIMessage messageVerifyer = new VerifyPKIMessage(caInfo, admin, caSession, endEntityAccessSession, certificateStoreSession, authorizationSession, endEntityProfileSession, authenticationProviderSession);
                ICMPAuthenticationModule authenticationModule = null;
                if(messageVerifyer.verify(msg.getMessage(), null)) {
                    authenticationModule = messageVerifyer.getUsedAuthenticationModule();
                }
                if(authenticationModule == null) {
                    String errMsg = "";

                    errMsg = messageVerifyer.getErrorMessage();
                    
                    LOG.error(errMsg);
                    return CmpMessageHelper.createUnprotectedErrorMessage(msg, ResponseStatus.FAILURE, FailInfo.BAD_MESSAGE_CHECK, errMsg);
                } else {
                    if(authenticationModule instanceof HMACAuthenticationModule) {
                        HMACAuthenticationModule hmacmodule = (HMACAuthenticationModule) authenticationModule;
                        owfAlg = hmacmodule.getCmpPbeVerifyer().getOwfOid();
                        macAlg = hmacmodule.getCmpPbeVerifyer().getMacOid();
					}
				}
                cmpRaAuthSecret = authenticationModule.getAuthenticationString();

			}
			if (LOG.isDebugEnabled()) {
				LOG.debug("Creating a PKI confirm message response");
			}
			CmpConfirmResponseMessage cresp = new CmpConfirmResponseMessage();
			cresp.setRecipientNonce(msg.getSenderNonce());
			cresp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
			cresp.setSender(msg.getRecipient());
			cresp.setRecipient(msg.getSender());
			cresp.setTransactionId(msg.getTransactionId());
			// Set all protection parameters
			if (LOG.isDebugEnabled()) {
				LOG.debug(responseProtection+", "+owfAlg+", "+macAlg+", "+keyId+", "+cmpRaAuthSecret);
			}
			if (StringUtils.equals(responseProtection, "pbe") && (owfAlg != null) && (macAlg != null) && (keyId != null) && (cmpRaAuthSecret != null) ) {
				cresp.setPbeParameters(keyId, cmpRaAuthSecret, owfAlg, macAlg, iterationCount);
			} else if (StringUtils.equals(responseProtection, "signature")) {
				try {
					// Get the CA that should sign the response
					String cadn = CertTools.stringToBCDNString(msg.getRecipient().getName().toString());
					CA ca = null;
					if (cadn == null) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Using Default CA to sign Certificate Confirm message: "+CmpConfiguration.getDefaultCA());
						}
						ca = caSession.getCA(admin, CmpConfiguration.getDefaultCA());
					} else if (CmpConfiguration.getDefaultCA() != null) {
						if (LOG.isDebugEnabled()) {
							LOG.debug("Using recipient CA to sign Certificate Confirm message: '"+cadn+"', "+cadn.hashCode());
						}
						ca = caSession.getCA(admin, cadn.hashCode());
					}
					if (ca != null) {
						CAToken catoken = ca.getCAToken();
						cresp.setSignKeyInfo(ca.getCACertificate(), catoken.getPrivateKey(SecConst.CAKEYPURPOSE_CERTSIGN), catoken.getCryptoToken().getSignProviderName());						
					} else {
						if (LOG.isDebugEnabled()) {
							LOG.info("Could not find CA to sign Certificate Confirm, either from recipient ("+cadn+") or default ("+CmpConfiguration.getDefaultCA()+"). Not signing Certificate Confirm.");
						}
					}
				} catch (CADoesntExistsException e) {
					LOG.error("Exception during CMP response signing: ", e);			
				} catch (IllegalCryptoTokenException e) {
					LOG.error("Exception during CMP response signing: ", e);			
				} catch (CryptoTokenOfflineException e) {
				    LOG.error("Exception during CMP response signing: ", e);			
				} catch (AuthorizationDeniedException e) {
					LOG.error("Exception during CMP response signing: ", e);
				}
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
			} catch (IOException e) {
				LOG.error("Exception during CMP processing: ", e);			
			}							
		} else {
			if (LOG.isDebugEnabled()) {
				LOG.debug("Cmp1999 - Not creating a PKI confirm message response");
			}
		}
		return resp;
	}
}
