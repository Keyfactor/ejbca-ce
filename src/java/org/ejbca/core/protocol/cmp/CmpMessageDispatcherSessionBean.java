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

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERObject;
import org.cesecore.core.ejb.ca.store.CertificateProfileSessionLocal;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.ra.CertificateRequestSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.CryptoProviderTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;

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
 * @author tomas
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CmpMessageDispatcherSessionRemote")
public class CmpMessageDispatcherSessionBean implements CmpMessageDispatcherSessionLocal, CmpMessageDispatcherSessionRemote {

	private static final Logger log = Logger.getLogger(CmpMessageDispatcherSessionBean.class);
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();
	
	/** This defines if we allows messages that has a POPO setting of raVerify. 
	 * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
	 */
	private boolean allowRaVerifyPopo = CmpConfiguration.getAllowRAVerifyPOPO();
	/** The default CA used for signing requests, if it is not given in the request itself. */
	private String defaultCA = CmpConfiguration.getDefaultCA();
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = CmpConfiguration.getExtractUsernameComponent();
	
    @EJB
	private SignSessionLocal signSession;
	@EJB
	private UserAdminSessionLocal userAdminSession;
	@EJB
	private CAAdminSessionLocal caAdminSession;
	@EJB
	private EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB
	private CertificateProfileSessionLocal certificateProfileSession;
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;
	@EJB
	private CertificateRequestSessionLocal certificateRequestSession;
	
	@PostConstruct
	public void postConstruct() {
		CryptoProviderTools.installBCProviderIfNotAvailable();	// Install BouncyCastle provider, if not already available
	}

	/** The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
	 * 
	 * @param message der encoded CMP message as a byte array
	 * @return IResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
	 */
	public IResponseMessage dispatch(Admin admin, byte[] derObject) {
		DERObject arg = null;
		try {
			arg = ASN1Sequence.fromByteArray(derObject).getDERObject();
		} catch (IOException e) {
			log.error("Could not parse byte array as ASN1Sequence.", e);
		}
		return dispatch(admin, arg);
	}

	/** The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
	 * 
	 * @param message der encoded CMP message
	 * @return IResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
	 */
	private IResponseMessage dispatch(Admin admin, DERObject derObject) {
		final PKIMessage req;
		try {
			req = PKIMessage.getInstance(derObject);
			if ( req==null ) {
				throw new Exception("No CMP message could be parsed from received Der object.");
			}
		} catch (Throwable t) {
			final String eMsg = intres.getLocalizedMessage("cmp.errornotcmpmessage");
			log.error(eMsg, t);
			// If we could not read the message, we should return an error BAD_REQUEST
			return CmpMessageHelper.createUnprotectedErrorMessage(null, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, eMsg);
		}
		try {
			PKIHeader header = req.getHeader();
			PKIBody body = req.getBody();
			
			int tagno = body.getTagNo();
			if (log.isDebugEnabled()) {
				log.debug("Received CMP message with pvno="+header.getPvno()+", sender="+header.getSender().toString()+", recipient="+header.getRecipient().toString());
				log.debug("Body is of type: "+tagno);
				log.debug(req);
				//log.debug(ASN1Dump.dumpAsString(req));				
			}
			BaseCmpMessage cmpMessage = null;
			ICmpMessageHandler handler = null;
			int unknownMessageType = -1;
			switch (tagno) {
			case 0:
				// 0 and 2 are both certificate requests
				handler = new CrmfMessageHandler(admin, caAdminSession,  certificateProfileSession, certificateRequestSession, endEntityProfileSession, signSession, userAdminSession);
				cmpMessage = new CrmfRequestMessage(req, defaultCA, allowRaVerifyPopo, extractUsernameComponent);
				break;
			case 2:
				handler = new CrmfMessageHandler(admin, caAdminSession, certificateProfileSession, certificateRequestSession, endEntityProfileSession, signSession, userAdminSession);
				cmpMessage = new CrmfRequestMessage(req, defaultCA, allowRaVerifyPopo, extractUsernameComponent);
				break;
			case 19:
				// PKI confirm
				handler = new ConfirmationMessageHandler();
				cmpMessage = new GeneralCmpMessage(req);
				break;
			case 24:
				// Certificate confirmation
				handler = new ConfirmationMessageHandler();
				cmpMessage = new GeneralCmpMessage(req);
				break;
			case 11:
				// Revocation request
				handler = new RevocationMessageHandler(admin, certificateStoreSession, userAdminSession);
				cmpMessage = new GeneralCmpMessage(req);
				break;
			default:
				unknownMessageType = tagno;
				log.info("Received an unknown message type, tagno="+tagno);
				break;
			}
			if ( handler==null || cmpMessage==null ) {
				if (unknownMessageType > -1) {
					final String eMsg = intres.getLocalizedMessage("cmp.errortypenohandle", new Integer(unknownMessageType));
					log.error(eMsg);
					return CmpMessageHelper.createUnprotectedErrorMessage(null, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, eMsg);
				}
				throw new Exception("Something is null! Handler="+handler+", cmpMessage="+cmpMessage);
			}
			final IResponseMessage ret  = handler.handleMessage(cmpMessage);
			if (ret != null) {
				log.debug("Received a response message from CmpMessageHandler.");
			} else {
				log.error( intres.getLocalizedMessage("cmp.errorresponsenull") );
			}
			return ret;
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage("cmp.errorprocess"), e);
			return null;
		}
	}
}
