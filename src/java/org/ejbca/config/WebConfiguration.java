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

package org.ejbca.config;

public class WebConfiguration {

	public static boolean getRequireAdminCertificateInDatabase() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("web.reqcertindb", "true"));
	}

	public static String getMailMimeType(){
	   	return "text/plain;charset=" + ConfigurationHolder.getString ("web.contentencoding", "UTF-8");
	}

}
