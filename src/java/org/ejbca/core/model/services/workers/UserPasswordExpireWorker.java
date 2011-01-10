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
package org.ejbca.core.model.services.workers;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UserNotificationParamGen;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.actions.MailActionInfo;

/**
 * Worker expiring users password after a configured amount of time.
 * 
 * Makes queries for users with status new, which was not modified in a certain amount of time, and sets
 * the status of these users to generated. Can be used for the following scenario:
 * - A user is generated and given username password to fetch the certificates
 * - If the user does not fetch his certificate within a configured amount of time the user is expired and is not allowed to fetch the certificate any more
 * 
 * @author Tomas Gustavsson based on code by Philip Vendil
 *
 * @version: $Id$
 */
public class UserPasswordExpireWorker extends EmailSendingWorker {

    private static final Logger log = Logger.getLogger(UserPasswordExpireWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Worker that makes a query to the Certificate Store about expiring
     * certificates.
     * 
     * @see org.ejbca.core.model.services.IWorker#work()
     */
    public void work() throws ServiceExecutionFailedException {
        log.trace(">Worker started");

        ArrayList<EmailCertData> userEmailQueue = new ArrayList<EmailCertData>();
        ArrayList<EmailCertData> adminEmailQueue = new ArrayList<EmailCertData>();
       
        long timeModified = ((new Date()).getTime() - getTimeBeforeExpire());   
        List<UserDataVO> userDataList = getUserAdminSession().findUsers(new ArrayList<Integer>(getCAIdsToCheck(false)),
                timeModified, UserDataConstants.STATUS_NEW);

        for (UserDataVO userDataVO : userDataList) {
            userDataVO.setStatus(UserDataConstants.STATUS_GENERATED);
            userDataVO.setPassword(null);
            try {
                getUserAdminSession().changeUser(getAdmin(), userDataVO, false);
                if (isSendToEndUsers()) {
                	if (userDataVO.getEmail() == null || userDataVO.getEmail().trim().equals("")) {
                		String msg = intres.getLocalizedMessage("services.errorworker.errornoemail", userDataVO.getUsername());
                		log.info(msg);
                	} else {
                		// Populate end user message
                		String message = new UserNotificationParamGen(userDataVO).interpolate(getEndUserMessage());
                		MailActionInfo mailActionInfo = new MailActionInfo(userDataVO.getEmail(), getEndUserSubject(), message);
                		userEmailQueue.add(new EmailCertData(userDataVO.getUsername(), mailActionInfo));
                	}
                }
                if (isSendToAdmins()) {
                	// Populate admin message
                	String message = new UserNotificationParamGen(userDataVO).interpolate(getAdminMessage());
                	MailActionInfo mailActionInfo = new MailActionInfo(null, getAdminSubject(), message);
                	adminEmailQueue.add(new EmailCertData(userDataVO.getUsername(), mailActionInfo));
                }
            } catch (Exception e) {
                log.error("Error running service work: ", e);
                throw new ServiceExecutionFailedException(e);
            }
        }

        // Send of the mails
        if (isSendToEndUsers()) {
            sendEmails(userEmailQueue);
        }
        if (isSendToAdmins()) {
            sendEmails(adminEmailQueue);
        }

        log.trace("<Worker ended");
    }
	
	/** Method that must be implemented by all subclasses to EmailSendingWorker, used to update status of 
	 * a certificate, user, or similar
	 * @param pk primary key of object to update
	 * @param status status to update to 
	 */
	protected void updateStatus(String pk, int status) {
		// Do nothing
	}

}
