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

import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.Base64;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: ConfirmationMessageHandler.java,v 1.1 2006-09-21 11:33:33 anatom Exp $
 */
public class ConfirmationMessageHandler implements ICmpMessageHandler {
	
	private static Logger log = Logger.getLogger(ConfirmationMessageHandler.class);
	
	public ConfirmationMessageHandler() throws CreateException {
	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		log.debug(">handleMessage");
		CmpConfirmResponseMessage resp = new CmpConfirmResponseMessage();
		resp.setRecipientNonce(msg.getSenderNonce());
		resp.setSenderNonce(new String(Base64.encode(CmpMessageHelper.createSenderNonce())));
		resp.setSender(msg.getRecipient());
		resp.setRecipient(msg.getSender());
		resp.setTransactionId(msg.getTransactionId());
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
