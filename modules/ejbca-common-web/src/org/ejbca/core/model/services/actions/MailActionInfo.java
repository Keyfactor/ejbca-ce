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
package org.ejbca.core.model.services.actions;

import org.ejbca.core.model.services.ActionInfo;

/**
 * Class containing information that is sent between a worker and
 * the MailAction action.
 * 
 * 
 * @version $Id$
 */
public class MailActionInfo implements ActionInfo {
	
	private static final long serialVersionUID = -6111022918482039456L;
    private String reciever = null;
	private String subject = null;
	private String message = null;
	private boolean isLoggingEnabled = true;
	
	/**
	 * Constructor used to create a MailActionInfo
	 * 
	 * @param reciever the reciever of the message, if null will the MailAction configured reciever be used.
	 * @param subject the subject of the mail
	 * @param message the message of the mail.
	 */
	public MailActionInfo(String reciever, String subject, String message) {
		super();
		this.reciever = reciever;
		this.subject = subject;
		this.message = message;
	}

   /**
    * @return  the message of the mail.
    */
	public String getMessage() {
		return message;
	}

	/**
	 * 
	 * @return the reciever of the message, if null will the MailAction configured reciever be used.
	 */

	public String getReciever() {
		return reciever;
	}

    /**
     * @return the subject of the mail
     */
	public String getSubject() {
		return subject;
	}

	/**
	 * Default logging is enabled.
	 * @param flag is set to false to disable logging
	 */
	public void setLoggingEnabled(boolean flag) {
		isLoggingEnabled = flag;
	}
	
	public boolean isLoggingEnabled() {
		return isLoggingEnabled;
	}
	
	

}
