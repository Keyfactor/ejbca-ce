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
import java.rmi.RemoteException;
import java.util.Properties;

import javax.ejb.CreateException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.FailInfo;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.util.CertTools;

import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Class that receives a CMP message and passes it on to the correct message handler.
 * 
 * ----- 
 * This processes does the following: 
 * 1. receive a CMP message 
 * 2. check wich message type it is 
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
 * @version $Id: CmpMessageDispatcher.java,v 1.10 2006-11-02 17:03:02 anatom Exp $
 */
public class CmpMessageDispatcher {
	private static final Logger log = Logger.getLogger(CmpMessageDispatcher.class);
	
	/** This defines if we allows messages that has a POPO setting of raVerify. 
	 * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
	 */
	private boolean allowRaVerifyPopo = false;
	/** The default CA used for signing requests, if it is not given in the request itself. */
	private String defaultCA = null;
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = null;
	private Admin admin;
	/** Configuration properties passed from higher class, used to configure message handlers as well */
	private Properties properties;
	
	public CmpMessageDispatcher(Admin adm, Properties prop) {
		this.admin = adm;
		this.properties = prop;
		// Install BouncyCastle provider
		CertTools.installBCProvider();
		
		// Read parameters 
		String str = prop.getProperty("allowRaVerifyPopo");
		if (StringUtils.equals("true", str)) {
			log.debug("allowRAVerifyPopo=true");
			allowRaVerifyPopo = true;
		}
		str = prop.getProperty("defaultCA");
		log.debug("defaultCA="+str);
		if (StringUtils.isNotEmpty(str)) {
			defaultCA = str;
		}
		str = prop.getProperty("extractUsernameComponent");
		log.debug("extractUsernameComponent="+str);
		if (StringUtils.isNotEmpty(str)) {
			extractUsernameComponent = str;
		}
	}
	
	/** The message may have been received by any transport protocol, and is passed here in it's binary asn.1 form.
	 * 
	 * @param message der encoded CMP message
	 * @return IResponseMessage containing the CMP response message or null if there is no message to send back
	 */
	public IResponseMessage dispatch(byte[] message) {
		IResponseMessage ret = null;
		try {
			PKIMessage req = null;
			try {
				req = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(message)).readObject());				
			} catch (Exception e) {
				// If we could not read the message, we should return an error BAD_REQUEST
				ret = CmpMessageHelper.createUnprotectedErrorMessage(null, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, "Can not parse request message");
				return ret;
			}
			PKIHeader header = req.getHeader();
			PKIBody body = req.getBody();
			
			int tagno = -1;
			if (log.isDebugEnabled()) {
				tagno = body.getTagNo();
				log.debug("Received CMP message with pvno="+header.getPvno()+", sender="+header.getSender()+", recipient="+header.getRecipient());
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
				handler = new CrmfMessageHandler(admin, properties);
				cmpMessage = new CrmfRequestMessage(req, defaultCA, allowRaVerifyPopo, extractUsernameComponent);
				break;
			case 2:
				handler = new CrmfMessageHandler(admin, properties);
				cmpMessage = new CrmfRequestMessage(req, defaultCA, allowRaVerifyPopo, extractUsernameComponent);
				break;
			case 19:
				// PKI confirm
				handler = new ConfirmationMessageHandler(properties);
				cmpMessage = new GeneralCmpMessage(req);
				break;
			case 24:
				// Certificate confirmation
				handler = new ConfirmationMessageHandler(properties);
				cmpMessage = new GeneralCmpMessage(req);
				break;
			case 11:
				// Revocation request
				handler = new RevocationMessageHandler(admin, properties);
				cmpMessage = new GeneralCmpMessage(req);
				break;
			default:
				unknownMessageType = tagno;
				break;
			}
			if ( (handler != null) && (cmpMessage != null) ) {
				ret  = handler.handleMessage(cmpMessage);
				if (ret != null) {
					log.debug("Received a response message from CmpMessageHandler.");
				} else {
					log.error("CmpMessageHandler returned a null message");
				}
			} else {
				log.error("Something is null! Handler="+handler+", cmpMessage="+cmpMessage);
				if (unknownMessageType > -1) {
					log.error("Unknown message type "+unknownMessageType+" received, creating error message");
					ret = CmpMessageHelper.createUnprotectedErrorMessage(null, ResponseStatus.FAILURE, FailInfo.BAD_REQUEST, "Can not handle message type");					
				}

			}
		} catch (CreateException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (RemoteException e) {
			log.error("Exception during CMP processing: ", e);
		}

		return ret;
	}
	
}
