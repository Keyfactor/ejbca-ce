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
 * This file handles configuration from internal.properties
 *
 * @version $Id$
 */
public class InternalConfiguration {

    public static final String CONFIG_APPNAME_CAPITAL = "app.name.capital";
	public static final String CONFIG_DATASOURCENAMEPREFIX = "datasource.jndi-name-prefix";

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
		return EjbcaConfigurationHolder.getExpandedString(CONFIG_APPNAME_CAPITAL);
	}

	/**
	 * Application version number
	 */
	public static String getAppVersionNumber() {
		return EjbcaConfigurationHolder.getExpandedString("app.version.number");
	}

	/**
	 * SVN revision
	 */
	public static String getSvnRevision() {
		return EjbcaConfigurationHolder.getExpandedString("svn.revision");
	}

	/**
	 * Full application version
	 */
	public static String getAppVersion() {
		return EjbcaConfigurationHolder.getExpandedString("app.version");
	}

	public static String getDataSourceJndiNamePrefix(){
		return EjbcaConfigurationHolder.getString(CONFIG_DATASOURCENAMEPREFIX);	// We need to return an empty string for WebLogic. "java:/" will be set anyway on JBoss.
	}
}
