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
package org.ejbca.webtest;

import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.ejbca.webtest.utils.ConfigurationHolder;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.internal.ProfilesIni;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Base class to be used by all automated Selenium tests. Should be extended for each test case.
 *
 * @version $Id: WebTestBase.java 28846 2018-05-04 11:32:25Z andrey_s_helmes $
 */
public abstract class WebTestBase {

    private static ConfigurationHolder config;

    private static String ejbcaDomain;
    private static String ejbcaSslPort;
    private static String ejbcaPort;
    private static String downloadDir;

    private static WebDriver webDriver;
    private static WebDriverWait webDriverWait;

    protected static final AuthenticationToken ADMIN_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    /**
     * Sets up firefox driver and firefox profile if certificate is required
     * @param requireCert if certificate is required
     * @param profile browser profile to use. Defined in ConfigurationConstants, null will use default profile.
     */
    public static void setUp(boolean requireCert, String profile) {
        // Init properties
        setGlobalConstants();
        // Init gecko driver
        config.setGeckoDriver();
        if (requireCert) {
            ProfilesIni allProfiles = new ProfilesIni();
            FirefoxProfile firefoxProfile;
            if (profile != null) {
                firefoxProfile = allProfiles.getProfile(config.getProperty(profile));
            } else {
                firefoxProfile = allProfiles.getProfile(config.getProperty(ConfigurationConstants.PROFILE_FIREFOX_DEFAULT));
            }
            firefoxProfile.setPreference("security.default_personal_cert", "Select Automatically");
            firefoxProfile.setPreference("browser.download.folderList", 2);
            firefoxProfile.setPreference("browser.download.dir", downloadDir);
            firefoxProfile.setPreference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream");
            FirefoxOptions firefoxOptions = new FirefoxOptions();
            firefoxOptions.setProfile(firefoxProfile);
            firefoxOptions.setAcceptInsecureCerts(true);
            webDriver = new FirefoxDriver(firefoxOptions);
        } else {
            webDriver = new FirefoxDriver();
        }

        webDriver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
        webDriverWait = new WebDriverWait(webDriver, 5, 50);
    }

    public static void tearDown() {
        // Destroy web driver & close all windows
        webDriver.quit();
    }

    private static void setGlobalConstants() {
        config = new ConfigurationHolder();
        config.loadAllProperties();
        ejbcaDomain = config.getProperty(ConfigurationConstants.APPSERVER_DOMAIN);
        ejbcaPort = config.getProperty(ConfigurationConstants.APPSERVER_PORT);
        ejbcaSslPort = config.getProperty(ConfigurationConstants.APPSERVER_PORT_SSL);
        downloadDir = config.getProperty(ConfigurationConstants.BROWSER_DOWNLOADDIR);
    }

    public String getCaName() {
        return config.getProperty(ConfigurationConstants.EJBCA_CANAME);
    }

    public String getCaDn() {
        return config.getProperty(ConfigurationConstants.EJBCA_CADN);
    }

    /**
     * @param constantKey profile key from ConfigurationConstants
     * @return the profile name
     */
    public String getProfileName(String constantKey) {
        return config.getProperty(constantKey);
    }

    /**
     * <p>Get the namespace in which the administrative roles for clicktests reside, or null if no
     * namespace has been specified by the user.
     * <p>The namespace setting is fetched from the <code>ejbca.properties</code> configuration file.
     * @return the role namespace or null if no particular namespace has been configured by the user
     */
    public String getNamespace() {
        final String namespace = config.getProperty(ConfigurationConstants.EJBCA_NAMESPACE);
        return StringUtils.isBlank(namespace) ? null : namespace;
    }

    public String getPublicWebUrl() {
        return "http://" + ejbcaDomain + ":" + ejbcaPort + "/ejbca/";
    }

    public String getAdminWebUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSslPort + "/ejbca/adminweb";
    }

    public String getRaWebUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSslPort + "/ejbca/ra/";
    }

    public String getDownloadDir() {
        return downloadDir;
    }

    public static WebDriver getWebDriver() {
        return webDriver;
    }

    public static WebDriverWait getWebDriverWait() {
        return webDriverWait;
    }
}
