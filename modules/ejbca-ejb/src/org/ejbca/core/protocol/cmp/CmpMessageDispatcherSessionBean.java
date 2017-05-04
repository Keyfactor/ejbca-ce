/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.security.cert.CertificateEncodingException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Class that receives a CMP message and passes it on to the correct message handler.
 * 
 * ----- 
 * This processes does the following: 
 * 1. receive a CMP message 
 * 2. check which message type it is 
 * 3. dispatch to the correct message handler 
 * 4. send back the response received from the handler 
 * -----
 * 
 * Messages supported:
 * - Initialization Request - will return an Initialization Response
 * - Revocation Request - will return a Revocation Response
 * - PKI Confirmation - same as certificate confirmation accept - will return a PKIConfirm
 * - Certificate Confirmation - accept or reject by client - will return a PKIConfirm
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CmpMessageDispatcherSessionRemote")
public class CmpMessageDispatcherSessionBean implements CmpMessageDispatcherSessionLocal, CmpMessageDispatcherSessionRemote {

	private static final Logger log = Logger.getLogger(CmpMessageDispatcherSessionBean.class);
	/** Internal localization of logs and errors */
	private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	
    @EJB
    private EjbBridgeSessionLocal ejbBridgeSession;
	@EJB
	private CertificateRequestSessionLocal certificateRequestSession;
	@EJB
	private CryptoTokenSessionLocal cryptoTokenSession;
	@EJB
	private GlobalConfigurationSessionLocal globalConfigSession;

	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public byte[] dispatchRequest(final AuthenticationToken authenticationToken, final byte[] pkiMessageBytes, final String cmpConfigurationAlias) throws NoSuchAliasException {
        final CmpConfiguration cmpConfiguration = (CmpConfiguration) this.globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        if (!cmpConfiguration.aliasExists(cmpConfigurationAlias)) {
            final String msg = intres.getLocalizedMessage("cmp.nosuchalias", cmpConfigurationAlias);
            log.info(msg);
            throw new NoSuchAliasException(msg);
        }
        final PKIMessage pkiMessage = CmpMessageHelper.getPkiMessageFromBytes(pkiMessageBytes, false);
        if (pkiMessage == null) {
            // Log that we handled a bad request and respond to the client
            final String msg = intres.getLocalizedMessage("cmp.errornotcmpmessage");
            log.info(msg);
            return CmpMessageHelper.createUnprotectedErrorMessage(FailInfo.BAD_REQUEST, msg).getResponseMessage();
        } else {
            final ResponseMessage responseMessage = dispatch(authenticationToken, pkiMessage, cmpConfiguration, cmpConfigurationAlias, /*levelOfNesting=*/0);
            if (responseMessage!=null) {
                try {
                    return responseMessage.getResponseMessage();
                } catch (CertificateEncodingException e) {
                    log.warn(e.getMessage());
                    return CmpMessageHelper.createUnprotectedErrorMessage(FailInfo.BAD_REQUEST, e.getMessage()).getResponseMessage();
                }
            }
        }
        return null;
	}

	/**
	 * The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
	 * 
	 * @param authenticationToken
	 * @param pkiMessage DER encoded CMP message
	 * @param cmpConfigurationAlias the cmp alias we want to use for this request
     * @param levelOfNesting
	 * @return ResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
	 */
	private ResponseMessage dispatch(final AuthenticationToken authenticationToken, final PKIMessage pkiMessage, final CmpConfiguration cmpConfiguration,
	        String cmpConfigurationAlias, final int levelOfNesting) {
	    if (levelOfNesting>CmpMessageHelper.MAX_LEVEL_OF_NESTING) {
            return CmpMessageHelper.createUnprotectedErrorMessage(FailInfo.BAD_REQUEST, "Rejected request due to unreasonable level of nesting.");
	    }
	    final boolean authenticated = levelOfNesting>0;
		try {
            final PKIBody pkiBody = pkiMessage.getBody();
			final int tagno = pkiBody.getType();
			if (log.isDebugEnabled()) {
	            final PKIHeader pkiHeader = pkiMessage.getHeader();
				log.debug("Received CMP message with pvno="+pkiHeader.getPvno()+", sender="+pkiHeader.getSender().toString()+", recipient="+pkiHeader.getRecipient().toString());
				log.debug("Cmp configuration alias: " + cmpConfigurationAlias);
				log.debug("The CMP message is already authenticated: " + authenticated);
				log.debug("Body is of type: " + tagno);
				log.debug("Transaction id: " + pkiHeader.getTransactionID());
				if (log.isTraceEnabled()) {
	                log.trace(ASN1Dump.dumpAsString(pkiMessage));
				}
			}
			BaseCmpMessage cmpMessage = null;
			ICmpMessageHandler handler = null;
			int unknownMessageType = -1;
			switch (tagno) {
			case PKIBody.TYPE_INIT_REQ:
				// 0: ir, Initialization Request and 2 (cr, Certification Req) are both certificate requests
				handler = new CrmfMessageHandler(authenticationToken, cmpConfiguration, cmpConfigurationAlias, ejbBridgeSession, certificateRequestSession);
				cmpMessage = new CrmfRequestMessage(pkiMessage, cmpConfiguration.getCMPDefaultCA(cmpConfigurationAlias), cmpConfiguration.getAllowRAVerifyPOPO(cmpConfigurationAlias), cmpConfiguration.getExtractUsernameComponent(cmpConfigurationAlias));
				break;
			case PKIBody.TYPE_CERT_REQ:
			    // 2:
				handler = new CrmfMessageHandler(authenticationToken, cmpConfiguration, cmpConfigurationAlias, ejbBridgeSession, certificateRequestSession);
				cmpMessage = new CrmfRequestMessage(pkiMessage, cmpConfiguration.getCMPDefaultCA(cmpConfigurationAlias), cmpConfiguration.getAllowRAVerifyPOPO(cmpConfigurationAlias), cmpConfiguration.getExtractUsernameComponent(cmpConfigurationAlias));
				break;
			case PKIBody.TYPE_KEY_UPDATE_REQ:
			    // 7: Key Update request (kur, Key Update Request)
			    handler = new CrmfKeyUpdateHandler(authenticationToken, cmpConfiguration, cmpConfigurationAlias, ejbBridgeSession);
			    cmpMessage = new CrmfRequestMessage(pkiMessage, cmpConfiguration.getCMPDefaultCA(cmpConfigurationAlias), cmpConfiguration.getAllowRAVerifyPOPO(cmpConfigurationAlias), cmpConfiguration.getExtractUsernameComponent(cmpConfigurationAlias));
			    break;
			case PKIBody.TYPE_CONFIRM:
				// 19: PKI confirm (pkiconf, Confirmation)
			case PKIBody.TYPE_CERT_CONFIRM:
				// 24: Certificate confirmation (certConf, Certificate confirm)
			    handler = new ConfirmationMessageHandler(authenticationToken, cmpConfiguration, cmpConfigurationAlias, ejbBridgeSession, cryptoTokenSession);
			    cmpMessage = new GeneralCmpMessage(pkiMessage);
				break;
			case PKIBody.TYPE_REVOCATION_REQ:
				// 11: Revocation request (rr, Revocation Request)
				handler = new RevocationMessageHandler(authenticationToken, cmpConfiguration, cmpConfigurationAlias, ejbBridgeSession, cryptoTokenSession);
				cmpMessage = new GeneralCmpMessage(pkiMessage);
				break;
            case PKIBody.TYPE_NESTED:
                // 20: NestedMessageContent (nested)
                if (log.isDebugEnabled()) {
                    log.debug("Received a NestedMessageContent");
                }
                final NestedMessageContent nestedMessage = new NestedMessageContent(pkiMessage, cmpConfiguration, cmpConfigurationAlias);
                if (nestedMessage.verify()) {
                    if (log.isDebugEnabled()) {
                        log.debug("The NestedMessageContent was verified successfully");
                    }
                    try {
                        final PKIMessages nestedPkiMessages = PKIMessages.getInstance(pkiMessage.getBody().getContent());
                        final PKIMessage nestedPkiMessage = nestedPkiMessages.toPKIMessageArray()[0];
                        return dispatch(authenticationToken, nestedPkiMessage, cmpConfiguration, cmpConfigurationAlias, levelOfNesting+1);
                    } catch (IllegalArgumentException e) {
                        final String errMsg = e.getMessage();
                        log.info(errMsg, e);
                        return CmpMessageHelper.createUnprotectedErrorMessage(pkiMessage.getHeader(), FailInfo.BAD_REQUEST, errMsg); 
                    }
                }
                final String errMsg = "Could not verify the RA, signature verification on NestedMessageContent failed.";
                log.info(errMsg);
                return CmpMessageHelper.createUnprotectedErrorMessage(pkiMessage.getHeader(), FailInfo.BAD_REQUEST, errMsg);
			default:
				unknownMessageType = tagno;
				log.info("Received an unknown message type, tagno="+tagno);
				break;
			}
			if (handler==null || cmpMessage==null) {
				if (unknownMessageType > -1) {
					final String eMsg = intres.getLocalizedMessage("cmp.errortypenohandle", Integer.valueOf(unknownMessageType));
					log.error(eMsg);
					return CmpMessageHelper.createUnprotectedErrorMessage(FailInfo.BAD_REQUEST, eMsg);
				}
				throw new IllegalStateException("Something is null! Handler="+handler+", cmpMessage="+cmpMessage);
			}
			final ResponseMessage ret = handler.handleMessage(cmpMessage, authenticated);
			if (ret == null) {
                log.error(intres.getLocalizedMessage("cmp.errorresponsenull"));
			} else {
			    if (log.isDebugEnabled()) {
	                log.debug("Received a response message of type '"+ret.getClass().getName()+"' from CmpMessageHandler.");
			    }
			}
			return ret;
		} catch (RuntimeException e) {
			log.error(intres.getLocalizedMessage("cmp.errorprocess"), e);
			return null;
		}
	}
}
