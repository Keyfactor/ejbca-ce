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

import java.io.IOException;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIMessages;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
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
	private SignSessionLocal signSession;
	@EJB
	private EndEntityManagementSessionLocal endEntityManagementSession;
	@EJB
	private CaSessionLocal caSession;
	@EJB
	private EndEntityAccessSessionLocal endEntityAccessSession;
	@EJB
	private EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB
	private CertificateProfileSessionLocal certificateProfileSession;
	@EJB
	private CertificateRequestSessionLocal certificateRequestSession;
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;
	@EJB
	private AccessControlSessionLocal authSession;
	@EJB
	private WebAuthenticationProviderSessionLocal authenticationProviderSession;
	@EJB
	private CryptoTokenSessionLocal cryptoTokenSession;
	@EJB
	private GlobalConfigurationSessionLocal globalConfigSession;
	
	private CmpConfiguration cmpConfiguration;
	
	@PostConstruct
	public void postConstruct() {
		CryptoProviderTools.installBCProviderIfNotAvailable();	// Install BouncyCastle provider, if not already available
		this.cmpConfiguration = (CmpConfiguration) this.globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
	}

	/** The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
	 * 
	 * @param ba der encoded CMP message as a byte array, length limit of this byte array must be enforced by caller
     * @param confAlias the cmp alias we want to use for this request
	 * @return IResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
	 * @throws IOException 
     * @throws NoSuchAliasException if the confAlias does not exist among configured cmp aliases
	 */
	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public ResponseMessage dispatch(final AuthenticationToken admin, final byte[] ba, String confAlias) throws IOException, NoSuchAliasException {
	    // Length limit of this byte array must be handled by calling servlet
		//ASN1Primitive derObject = new LimitLengthASN1Reader(new ByteArrayInputStream(ba), ba.length).readObject();
	    final ASN1Primitive derObject = getDERObject(ba);
		return dispatch(admin, derObject, false, confAlias);
	}

	/** The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
	 * 
	 * @param derObject der encoded CMP message
	 * @param authenticated
	 * @param confAlias the cmp alias we want to use for this request
	 * @return IResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
	 * @throws NoSuchAliasException if the confAlias does not exist among configured cmp aliases
	 */
	private ResponseMessage dispatch(final AuthenticationToken admin, final ASN1Primitive derObject, final boolean authenticated, String confAlias) throws NoSuchAliasException {
	    
        this.cmpConfiguration = (CmpConfiguration) this.globalConfigSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

	    if(!cmpConfiguration.aliasExists(confAlias)) {
	        final String msg = intres.getLocalizedMessage("cmp.nosuchalias");
	        log.info(msg);
	        throw new NoSuchAliasException(msg);
	    }
	    
		final PKIMessage req;
		try {
			req = PKIMessage.getInstance(derObject);
			if ( req==null ) {
				throw new IOException("No CMP message could be parsed from received DER object.");
			}
		} catch (Throwable t) { // NOPMD: catch all to report errors back to client
			final String eMsg = intres.getLocalizedMessage("cmp.errornotcmpmessage");
			log.error(eMsg, t);
			// If we could not read the message, we should return an error BAD_REQUEST
			return CmpMessageHelper.createUnprotectedErrorMessage(null, FailInfo.BAD_REQUEST, eMsg);
		}
		try {
			final PKIBody body = req.getBody();
			final int tagno = body.getType();
			if (log.isDebugEnabled()) {
	            final PKIHeader header = req.getHeader();
				log.debug("Received CMP message with pvno="+header.getPvno()+", sender="+header.getSender().toString()+", recipient="+header.getRecipient().toString());
				log.debug("Cmp configuration alias: " + confAlias);
				log.debug("The CMP message is already authenticated: " + authenticated);
				log.debug("Body is of type: "+tagno);
				log.debug("Transaction id: "+header.getTransactionID());
				//log.debug(ASN1Dump.dumpAsString(req));
			}
			
			BaseCmpMessage cmpMessage = null;
			ICmpMessageHandler handler = null;
			int unknownMessageType = -1;
			switch (tagno) {
			case 0:
				// 0 (ir, Initialization Request) and 2 (cr, Certification Req) are both certificate requests
				handler = new CrmfMessageHandler(admin, confAlias, caSession,  certificateProfileSession, certificateRequestSession, 
				                        endEntityAccessSession, endEntityProfileSession, signSession, certificateStoreSession, authSession, 
				                        authenticationProviderSession, endEntityManagementSession, globalConfigSession);
				cmpMessage = new CrmfRequestMessage(req, this.cmpConfiguration.getCMPDefaultCA(confAlias), this.cmpConfiguration.getAllowRAVerifyPOPO(confAlias), this.cmpConfiguration.getExtractUsernameComponent(confAlias));
				break;
			case 2:
				handler = new CrmfMessageHandler(admin, confAlias, caSession, certificateProfileSession, certificateRequestSession, 
				                        endEntityAccessSession, endEntityProfileSession, signSession, certificateStoreSession, authSession, 
				                        authenticationProviderSession, endEntityManagementSession, globalConfigSession);
				cmpMessage = new CrmfRequestMessage(req, this.cmpConfiguration.getCMPDefaultCA(confAlias), this.cmpConfiguration.getAllowRAVerifyPOPO(confAlias), this.cmpConfiguration.getExtractUsernameComponent(confAlias));
				break;
			case 7:
			    // Key Update request (kur, Key Update Request)
			    handler = new CrmfKeyUpdateHandler(admin, confAlias, caSession, certificateProfileSession, endEntityAccessSession, endEntityProfileSession, 
			                            signSession, certificateStoreSession, authSession, authenticationProviderSession, endEntityManagementSession, 
			                            globalConfigSession);
			    cmpMessage = new CrmfRequestMessage(req, this.cmpConfiguration.getCMPDefaultCA(confAlias), this.cmpConfiguration.getAllowRAVerifyPOPO(confAlias), this.cmpConfiguration.getExtractUsernameComponent(confAlias));
			    break;
			case 19:
				// PKI confirm (pkiconf, Confirmation)
			case 24:
				// Certificate confirmation (certConf, Certificate confirm)
			    handler = new ConfirmationMessageHandler(admin, confAlias, caSession, endEntityProfileSession, certificateProfileSession, 
			                           authSession, authenticationProviderSession, cryptoTokenSession, globalConfigSession);
			    cmpMessage = new GeneralCmpMessage(req);
				break;
			case 11:
				// Revocation request (rr, Revocation Request)
				handler = new RevocationMessageHandler(admin, confAlias, endEntityManagementSession, caSession, endEntityProfileSession, certificateProfileSession,
				        certificateStoreSession, authSession, endEntityAccessSession, authenticationProviderSession, cryptoTokenSession, globalConfigSession);
				cmpMessage = new GeneralCmpMessage(req);
				break;
            case 20:
                // NestedMessageContent (nested)
                if(log.isDebugEnabled()) {
                    log.debug("Received a NestedMessageContent");
                }

                final NestedMessageContent nestedMessage = new NestedMessageContent(req, confAlias, globalConfigSession);
                if(nestedMessage.verify()) {
                    if(log.isDebugEnabled()) {
                        log.debug("The NestedMessageContent was verified successfully");
                    }
                    try {
                        PKIMessages nestesMessages = (PKIMessages) nestedMessage.getPKIMessage().getBody().getContent();
                        PKIMessage msg = nestesMessages.toPKIMessageArray()[0];
                        return dispatch(admin, msg.toASN1Primitive(), true, confAlias);
                    } catch (IllegalArgumentException e) {
                        final String errMsg = e.getLocalizedMessage();
                        log.info(errMsg, e);
                        cmpMessage = new NestedMessageContent(req, confAlias, globalConfigSession);
                        return CmpMessageHelper.createUnprotectedErrorMessage(cmpMessage, FailInfo.BAD_REQUEST, errMsg); 
                    }
                } else {
                    final String errMsg = "Could not verify the RA, signature verification on NestedMessageContent failed.";
                    log.info(errMsg);
                    cmpMessage = new NestedMessageContent(req, confAlias, globalConfigSession);
                    return CmpMessageHelper.createUnprotectedErrorMessage(cmpMessage, FailInfo.BAD_REQUEST, errMsg);
                }

			default:
				unknownMessageType = tagno;
				log.info("Received an unknown message type, tagno="+tagno);
				break;
			}
			if ( handler==null || cmpMessage==null ) {
				if (unknownMessageType > -1) {
					final String eMsg = intres.getLocalizedMessage("cmp.errortypenohandle", Integer.valueOf(unknownMessageType));
					log.error(eMsg);
					return CmpMessageHelper.createUnprotectedErrorMessage(null, FailInfo.BAD_REQUEST, eMsg);
				}
				throw new Exception("Something is null! Handler="+handler+", cmpMessage="+cmpMessage);
			}
			final ResponseMessage ret  = handler.handleMessage(cmpMessage, authenticated);
			if (ret != null) {
				log.debug("Received a response message of type '"+ret.getClass().getName()+"' from CmpMessageHandler.");
			} else {
				log.error( intres.getLocalizedMessage("cmp.errorresponsenull") );
			}
			return ret;
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("cmp.errorprocess"), e);
			return null;
		}
	}
	
    private ASN1Primitive getDERObject(byte[] ba) throws IOException {
        ASN1InputStream ins = new ASN1InputStream(ba);
        try {
            ASN1Primitive obj = ins.readObject();
            return obj;
        } finally {
            ins.close();
        }
    }
}
