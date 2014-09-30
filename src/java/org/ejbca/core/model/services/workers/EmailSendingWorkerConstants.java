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

/**
 * @version $Id$
 */
public abstract class EmailSendingWorkerConstants {
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

}
