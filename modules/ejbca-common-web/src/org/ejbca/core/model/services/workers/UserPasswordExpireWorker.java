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
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
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

    /**
     * Worker that makes a query to the Certificate Store about expiring
     * certificates.
     * 
     * @see org.ejbca.core.model.services.IWorker#work()
     */
    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        log.trace(">Worker started");
        final EndEntityManagementSessionLocal endEntityManagementSession = ((EndEntityManagementSessionLocal)ejbs.get(EndEntityManagementSessionLocal.class));

        ArrayList<EmailCertData> userEmailQueue = new ArrayList<EmailCertData>();
        ArrayList<EmailCertData> adminEmailQueue = new ArrayList<EmailCertData>();
       
        long timeModified = ((new Date()).getTime() - getTimeBeforeExpire());   
        List<EndEntityInformation> userDataList = endEntityManagementSession.findUsers(new ArrayList<Integer>(getCAIdsToCheck(false)),
                timeModified, EndEntityConstants.STATUS_NEW);

        for (EndEntityInformation endEntityInformation : userDataList) {
            endEntityInformation.setStatus(EndEntityConstants.STATUS_GENERATED);
            endEntityInformation.setPassword(null);
            try {
            	endEntityManagementSession.changeUser(getAdmin(), endEntityInformation, false);
                if (isSendToEndUsers()) {
                	if (endEntityInformation.getEmail() == null || endEntityInformation.getEmail().trim().equals("")) {
                		log.info(InternalEjbcaResources.getInstance().getLocalizedMessage("services.errorworker.errornoemail", endEntityInformation.getUsername()));
                	} else {
                		// Populate end user message
                		String message = new UserNotificationParamGen(endEntityInformation).interpolate(getEndUserMessage());
                		MailActionInfo mailActionInfo = new MailActionInfo(endEntityInformation.getEmail(), getEndUserSubject(), message);
                		userEmailQueue.add(new EmailCertData(endEntityInformation.getUsername(), mailActionInfo));
                	}
                }
                if (isSendToAdmins()) {
                	// Populate admin message
                	String message = new UserNotificationParamGen(endEntityInformation).interpolate(getAdminMessage());
                	MailActionInfo mailActionInfo = new MailActionInfo(null, getAdminSubject(), message);
                	adminEmailQueue.add(new EmailCertData(endEntityInformation.getUsername(), mailActionInfo));
                }
            } catch (Exception e) {
                log.error("Error running service work: ", e);
                throw new ServiceExecutionFailedException(e);
            }
        }
        // Send of the mails
        if (isSendToEndUsers()) {
            sendEmails(userEmailQueue, ejbs);
        }
        if (isSendToAdmins()) {
            sendEmails(adminEmailQueue, ejbs);
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
