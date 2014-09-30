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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

import org.ejbca.core.model.services.actions.MailAction;

/**
 * Action type describing the mail notification action
 * 
 *
 * $Id$
 */
public class MailActionType extends ActionType {
	
	private static final long serialVersionUID = 5340503998099975329L;
    public static final String NAME = "MAILNOTIFICATIONACTION";

	public MailActionType(){
		super("mailaction.jsp", NAME, true);
	}
	
	private String senderAddress = "";
	private String recieverAddress = "";
	
	public String getRecieverAddress() {
		return recieverAddress;
	}


	public void setRecieverAddress(String recieverAddress) {
		this.recieverAddress = recieverAddress;
	}


	public String getSenderAddress() {
		return senderAddress;
	}


	public void setSenderAddress(String senderAddress) {
		this.senderAddress = senderAddress;
	}



	
	
	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getClassPath()
	 */
	public String getClassPath() {
		return org.ejbca.core.model.services.actions.MailAction.class.getName();
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {		
		Properties properties = new Properties();
		if(senderAddress == null || senderAddress.trim().equals("")){
			errorMessages.add("MAILACTIONSENDERADDRESSERR");
		}
		properties.setProperty(MailAction.PROP_SENDERADDRESS, senderAddress);
		properties.setProperty(MailAction.PROP_RECIEVERADDRESS, recieverAddress);
		
		return properties;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#isCustom()
	 */
	public boolean isCustom() {		
		return false;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {		
	   senderAddress = properties.getProperty(MailAction.PROP_SENDERADDRESS, "");
	   recieverAddress = properties.getProperty(MailAction.PROP_RECIEVERADDRESS, "");

	}

}
