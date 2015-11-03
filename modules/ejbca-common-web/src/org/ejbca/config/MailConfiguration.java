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

package org.ejbca.config;

/**
 * 
 * @version $Id$
 */

public class MailConfiguration {

	/**
	 * The JNDI-name used to send email notifications from EJBCA.
	 */
	public static String getMailJndiName() {
		return EjbcaConfigurationHolder.getExpandedString("mail.jndi-name");
	}

	/**
	 * Content encoding for the email message body.
	 */
	public static String getMailMimeType() {
		return "text/plain;charset=" + EjbcaConfigurationHolder.getExpandedString("mail.contentencoding");
	}

}
