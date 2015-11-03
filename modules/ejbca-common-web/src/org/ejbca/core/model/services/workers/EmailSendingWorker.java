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

package org.ejbca.core.model.services.workers;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;
import org.ejbca.core.model.services.workers.EmailSendingWorkerConstants;

/**
 * @version $Id$
 */
public abstract class EmailSendingWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(EmailSendingWorker.class);

	private transient String endUserSubject = null;
	private transient String adminSubject = null;
	private transient String endUserMessage = null;
	private transient String adminMessage = null;

	public EmailSendingWorker() {
		super();
	}

	class EmailCertData{
		
		private String fingerPrint = null;
		private MailActionInfo actionInfo = null;
		
		public EmailCertData(String fingerPrint, MailActionInfo actionInfo) {
			super();
			this.fingerPrint = fingerPrint;
			this.actionInfo = actionInfo;
		}

		public String getFingerPrint() {
			return fingerPrint;
		}

		public MailActionInfo getActionInfo() {
			return actionInfo;
		}
	}

	/** Method that must be implemented by all subclasses to EmailSendingWorker, used to update status of 
	 * a certificate, user, or similar
	 * @param pk primary key of object to update
	 * @param status status to update to 
	 */
	protected abstract void updateStatus(String pk, int status);
	
	protected void sendEmails(ArrayList<EmailCertData> queue, Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
		Iterator<EmailCertData> iter = queue.iterator();
		while(iter.hasNext()){			
			try{
				EmailCertData next = iter.next();								
				getAction().performAction(next.getActionInfo(), ejbs);
				updateStatus(next.getFingerPrint(), CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION);
			} catch (Exception fe) {
				log.error("Error sending emails: ", fe);
				throw new ServiceExecutionFailedException(fe);
			} 
		}
	}

	protected String getAdminMessage() {
		if(adminMessage == null){
			adminMessage =  properties.getProperty(EmailSendingWorkerConstants.PROP_ADMINMESSAGE,"No Message Configured");
		}		
		return adminMessage;
	}

	protected String getAdminSubject() {
		if(adminSubject == null){
			adminSubject =  properties.getProperty(EmailSendingWorkerConstants.PROP_ADMINSUBJECT,"No Subject Configured");
		}
		
		return adminSubject;
	}

	protected String getEndUserMessage() {
		if(endUserMessage == null){
			endUserMessage =  properties.getProperty(EmailSendingWorkerConstants.PROP_USERMESSAGE,"No Message Configured");
		}
		
		return endUserMessage;
	}

	protected String getEndUserSubject() {
		if(endUserSubject == null){
			endUserSubject =  properties.getProperty(EmailSendingWorkerConstants.PROP_USERSUBJECT,"No Subject Configured");
		}
		
		return endUserSubject;
	}

	protected boolean isSendToAdmins() {
		return properties.getProperty(EmailSendingWorkerConstants.PROP_SENDTOADMINS,"FALSE").equalsIgnoreCase("TRUE");
	}

	protected boolean isSendToEndUsers() {
		return properties.getProperty(EmailSendingWorkerConstants.PROP_SENDTOENDUSERS,"FALSE").equalsIgnoreCase("TRUE");
	}
}
