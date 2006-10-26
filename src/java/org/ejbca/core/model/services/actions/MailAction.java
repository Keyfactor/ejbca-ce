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

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.EJBException;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.ActionInfo;
import org.ejbca.core.model.services.BaseAction;
import org.ejbca.core.model.services.workers.DummyWorker;
import org.ejbca.util.CertTools;
import org.ejbca.util.NotificationParamGen;
import org.ejbca.util.TemplateMimeMessage;

/**
 * Class managing the sending of emails from a service.
 * 
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class MailAction extends BaseAction {
	
	private static final Logger log = Logger.getLogger(MailAction.class);
	
	private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
	
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
		
		MailActionInfo mailActionInfo = (MailActionInfo) actionInfo;
		String senderAddress = properties.getProperty(PROP_SENDERADDRESS);
		
		String reciverAddress = mailActionInfo.getReciever();
		if(reciverAddress== null){
			reciverAddress = properties.getProperty(PROP_RECIEVERADDRESS);
		}
				
		if(reciverAddress == null || reciverAddress.trim().equals("")){
			throw new ActionException("Error: No reciver address could be found.");
		}
		        
        try {
              String mailJndi = getLocator().getString("java:comp/env/MailJNDIName");
              Session mailSession = getLocator().getMailSession(mailJndi);              

              Message msg = new MimeMessage(mailSession);
              msg.setFrom(new InternetAddress(senderAddress));
              msg.addRecipients(javax.mail.Message.RecipientType.TO, InternetAddress.parse(reciverAddress, false));
              msg.setSubject(mailActionInfo.getSubject());
              msg.setContent(mailActionInfo.getMessage(), "text/plain");
              msg.setHeader("X-Mailer", "JavaMailer");
              msg.setSentDate(new Date());
              Transport.send(msg);

              getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_APPROVAL, new java.util.Date(), null, null, LogEntry.EVENT_INFO_NOTIFICATION, "Email Notification was sent to  " + reciverAddress + " successfully.");
            
        } catch (Exception e) {
            log.error("Error when sending mail action notification", e);
            try{
            	getLogSession().log(admin, admin.getCaId(), LogEntry.MODULE_APPROVAL, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_NOTIFICATION, "Error sending email notification to  " + reciverAddress + ".");
            }catch(Exception f){
                throw new EJBException(f);
            }
        }
        

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
