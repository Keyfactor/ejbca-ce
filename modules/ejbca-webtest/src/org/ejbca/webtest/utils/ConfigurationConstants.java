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
package org.ejbca.webtest.utils;


/**
 * Configuration constants for EJBCA web tests
 * @version $Id: ConfigurationConstants.java 28846 2018-05-04 11:32:25Z oskareriksson $
 */
public final class ConfigurationConstants {

    private ConfigurationConstants() {};

    // Browser Profile Constants
    public static final String PROFILE_FIREFOX_DEFAULT      = "profile.firefox.default";
    public static final String PROFILE_FIREFOX_AUDIOR       = "profile.firefox.auditor";
    public static final String PROFILE_FIREFOX_CAADMIN      = "profile.firefox.caadmin";
    public static final String PROFILE_FIREFOX_CUSTOM       = "profile.firefox.custom";
    public static final String PROFILE_FIREFOX_RAADMIN      = "profile.firefox.raadmin";
    public static final String PROFILE_FIREFOX_RAADMINALT   = "profile.firefox.raadminalt";
    public static final String PROFILE_FIREFOX_SUPERADMIN   = "profile.firefox.superadmin";
    public static final String PROFILE_FIREFOX_SUPERVISOR   = "profile.firefox.supervisor";

    // Application Server Constants
    public static final String APPSERVER_DOMAIN     = "appserver.domainname";
    public static final String APPSERVER_PORT       = "appserver.port";
    public static final String APPSERVER_PORT_SSL   = "appserver.secureport";

    // EJBCA Specific Constants
    public static final String EJBCA_CANAME     = "ejbca.ca.name";
    public static final String EJBCA_CADN       = "ejbca.ca.dn";
    public static final String EJBCA_NAMESPACE  = "ejbca.namespace";

    // Browser Constants
    public static final String BROWSER_BINARY  = "browser.firefox.binary";
    public static final String BROWSER_DOWNLOADDIR  = "browser.downloaddir";
    public static final String BROWSER_HEADLESS = "browser.headless";

    // Database Constants
    public static final String DATABASE_HOST = "database.host";
    public static final String DATABASE_PORT = "database.port";
    public static final String DATABASE_USERNAME = "database.username";
    public static final String DATABASE_PASSWORD = "database.password";
}
