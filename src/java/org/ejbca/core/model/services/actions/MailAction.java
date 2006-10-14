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
package org.ejbca.core.model.services.actions;

import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.ActionInfo;
import org.ejbca.core.model.services.BaseAction;

/**
 * Class managing the sending of emails from a service.
 * 
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class MailAction extends BaseAction {
	
	public static final String PROP_SENDERADDRESS   = "action.mail.senderAddress";
	public static final String PROP_RECIEVERADDRESS = "action.mail.recieverAddress";

	/**
	 * Sends the mail
	 * 
	 * Only supports the MailActionInfo othervise is ActionException thrown.
	 * 
	 * @see org.ejbca.core.model.services.IAction#performAction(org.ejbca.core.model.services.ActionInfo)
	 */
	public void performAction(ActionInfo actionInfo) throws ActionException {
		checkConfig(actionInfo);
		//TODO

	}
	
	/**
	 * Method that checks the configuration sets the variables and throws an exception
	 * if it's invalid
	 *  
	 * @param actionInfo
	 * @throws ActionException
	 */
	private void checkConfig(ActionInfo actionInfo) throws ActionException {
		if(!(actionInfo instanceof MailActionInfo)){
			throw new ActionException("Error: Only MailActionInfo is supported");
		}
		
		String senderAddress = properties.getProperty(PROP_SENDERADDRESS);
		if(senderAddress == null || senderAddress.trim().equals("")){
			throw new ActionException("Error: A sender address must be configured.");
		}
	}
	


}
