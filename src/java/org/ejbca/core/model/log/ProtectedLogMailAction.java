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
package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.actions.MailAction;
import org.ejbca.core.model.services.actions.MailActionInfo;

/**
 * Send an email based on configuration.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogMailAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222539L;

	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);

	private static final String MAILACTION_ERROR_FAILED				= "protectedlog.mafailed";
	private static final String MAILACTION_ERROR_CAUSE				= "protectedlog.macause";

	private String[] emailAddresses = ProtectedLogConfiguration.getMailActionEmailAddresses();
	private String emailSubject = ProtectedLogConfiguration.getMailActionEmailSubject();
	private String emailBody = ProtectedLogConfiguration.getMailActionEmailBody();
	private MailAction mailAction = null;
	
	public ProtectedLogMailAction() {
		mailAction = new MailAction();
		Properties properties = new Properties();
		properties.setProperty(MailAction.PROP_SENDERADDRESS, ProtectedLogConfiguration.getMailActionEmailSender());
		mailAction.init(properties, null);
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		if (log.isTraceEnabled()) {
			log.trace(">action " + causeIdentifier + " " + emailAddresses.length);
		}
		String emailMessage = emailBody + "\n\n" + intres.getLocalizedMessage(MAILACTION_ERROR_CAUSE, causeIdentifier) + " " + intres.getLocalizedMessage(causeIdentifier);
		for (int i=0; i<emailAddresses.length; i++) {
			try {
				MailActionInfo mailActionInfo = new MailActionInfo(emailAddresses[i], emailSubject, emailMessage);
				mailActionInfo.setLoggingEnabled(false);	// Required to avoid transaction deadlock
				mailAction.performAction(mailActionInfo);
			} catch (ActionException e) {
				log.error(intres.getLocalizedMessage(MAILACTION_ERROR_FAILED));
			}
		}
	}
}
