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

/**
 * This file handles configuration from internal.properties
 *
 * @version $Id$
 */
public class InternalConfiguration {

	public static final String CONFIG_DATASOURCENAMEPREFIX       = "datasource.jndi-name-prefix";

	/**
	 * Lower case application name
	 */
	public static String getAppNameLower() {
		return "ejbca";
	}

	/**
	 * Dynamic version of getAppNameLower() for use from JSP/JSF
	 */
	public String getAppNameLowerDynamic() {
		return InternalConfiguration.getAppNameLower();
	}

	/**
	 * Upper case application name
	 */
	public static String getAppNameCapital() {
		return "EJBCA";
	}

	/**
	 * Application version number
	 */
	public static String getAppVersionNumber() {
		return ConfigurationHolder.getExpandedString("app.version.number", "versionNotAvailable");
	}

	/**
	 * SVN revision
	 */
	public static String getSvnRevision() {
		return ConfigurationHolder.getExpandedString("svn.revision", "revisionNotAvailable");
	}

	/**
	 * Full application version
	 */
	public static String getAppVersion() {
		return ConfigurationHolder.getExpandedString("app.version", getAppNameCapital() + " " + getAppVersionNumber() + " (" + getSvnRevision() + ")");
	}

	public static String getDataSourceJndiNamePrefix(){
		return ConfigurationHolder.getString(CONFIG_DATASOURCENAMEPREFIX, "");	// We need to return an empty string for WebLogic. "java:/" will be set anyway on JBoss.
	}
}
