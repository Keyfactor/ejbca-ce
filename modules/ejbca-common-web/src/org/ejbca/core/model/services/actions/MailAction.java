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

import java.util.Arrays;
import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.ActionInfo;
import org.ejbca.core.model.services.BaseAction;
import org.ejbca.util.mail.MailException;
import org.ejbca.util.mail.MailSender;

/**
 * Class managing the sending of emails from a service.
 * 
 */
public class MailAction extends BaseAction {

    private static final Logger log = Logger.getLogger(MailAction.class);

    public static final String PROP_SENDERADDRESS = "action.mail.senderAddress";
    public static final String PROP_RECIEVERADDRESS = "action.mail.recieverAddress";

    /**
     * Sends the mail
     * 
     * Only supports the MailActionInfo otherwise is ActionException thrown.
     * 
     * @see org.ejbca.core.model.services.IAction#performAction(org.ejbca.core.model.services.ActionInfo)
     */
    public void performAction(ActionInfo actionInfo, Map<Class<?>, Object> ejbs) throws ActionException {
        checkConfig(actionInfo);

        MailActionInfo mailActionInfo = (MailActionInfo) actionInfo;
        String senderAddress = properties.getProperty(PROP_SENDERADDRESS);

        String reciverAddress = mailActionInfo.getReciever();
        if (reciverAddress == null) {
            reciverAddress = properties.getProperty(PROP_RECIEVERADDRESS);
        }

        if (reciverAddress == null || reciverAddress.trim().equals("")) {
            String msg = "Error: No receiver address could be found.";
            throw new ActionException(msg);
        }

        try {
            MailSender.sendMailOrThrow(senderAddress, Arrays.asList(reciverAddress), MailSender.NO_CC, mailActionInfo.getSubject(),
                    mailActionInfo.getMessage(), MailSender.NO_ATTACHMENTS);
            if (mailActionInfo.isLoggingEnabled()) {
                String logmsg = "Email Notification was sent to " + reciverAddress + " successfully.";
                log.info(logmsg);
            }
        } catch (MailException e) {
            String msg = "Error when sending mail action notification to " + reciverAddress + ".";
            log.info(msg, e);
        }
    }

    /**
     * Method that checks the configuration sets the variables and throws an exception if it's invalid
     * 
     * @param actionInfo
     * @throws ActionException
     */
    private void checkConfig(ActionInfo actionInfo) throws ActionException {
        if (!(actionInfo instanceof MailActionInfo)) {
            String msg = "Error: Only MailActionInfo is supported.";
            throw new ActionException(msg);
        }
        String senderAddress = properties.getProperty(PROP_SENDERADDRESS);
        if (senderAddress == null || senderAddress.trim().equals("")) {
            String msg = "Error: A sender address must be configured.";
            throw new ActionException(msg);
        }
    }
}
