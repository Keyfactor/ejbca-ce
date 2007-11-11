package org.ejbca.core.model.services.workers;


import java.util.ArrayList;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;

public abstract class EmailSendingWorker extends BaseWorker {

	/** Boolean indicating if a notification should be sent to the end user of the expiration */
	public static final String PROP_SENDTOENDUSERS     = "worker.mail.sendtoendusers";
	
	/** Boolean indicating if a notification should be sent to the administrators */ 
	public static final String PROP_SENDTOADMINS       = "worker.mail.sendtoadmins";
	
	/** The subject to use in the end user notification */
	public static final String PROP_USERSUBJECT        = "worker.mail.usersubject";
	
	/** The message to use in the end user notification. Substitution variables are possible in
	 * the same way as for regular notifications.*/
	public static final String PROP_USERMESSAGE        = "worker.mail.usermessage";
	
	/** The subject to use in the admin notification */
	public static final String PROP_ADMINSUBJECT       = "worker.mail.adminsubject";
	
	/** The message to use in the admin notification. Substitution variables are possible in
	 * the same way as for regular notifications.*/
	public static final String PROP_ADMINMESSAGE       = "worker.mail.adminmessage";		
	
	

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
	
	protected void sendEmails(ArrayList queue)
			throws ServiceExecutionFailedException {
				Iterator iter = queue.iterator();
				while(iter.hasNext()){			
					try{
						EmailCertData next = (EmailCertData) iter.next();								
						getAction().performAction(next.getActionInfo());
						updateStatus(next.getFingerPrint(), CertificateDataBean.CERT_NOTIFIEDABOUTEXPIRATION );
					} catch (Exception fe) {
						log.error("Error sending emails: ", fe);
						throw new ServiceExecutionFailedException(fe);
					} 
				}
			}

	protected String getAdminMessage() {
		if(adminMessage == null){
			adminMessage =  properties.getProperty(PROP_ADMINMESSAGE,"No Message Configured");
		}		
		return adminMessage;
	}

	protected String getAdminSubject() {
		if(adminSubject == null){
			adminSubject =  properties.getProperty(PROP_ADMINSUBJECT,"No Subject Configured");
		}
		
		return adminSubject;
	}

	protected String getEndUserMessage() {
		if(endUserMessage == null){
			endUserMessage =  properties.getProperty(PROP_USERMESSAGE,"No Message Configured");
		}
		
		return endUserMessage;
	}

	protected String getEndUserSubject() {
		if(endUserSubject == null){
			endUserSubject =  properties.getProperty(PROP_USERSUBJECT,"No Subject Configured");
		}
		
		return endUserSubject;
	}

	protected boolean isSendToAdmins() {
		return properties.getProperty(PROP_SENDTOADMINS,"FALSE").equalsIgnoreCase("TRUE");
	}

	protected boolean isSendToEndUsers() {
		return properties.getProperty(PROP_SENDTOENDUSERS,"FALSE").equalsIgnoreCase("TRUE");
	}

}
