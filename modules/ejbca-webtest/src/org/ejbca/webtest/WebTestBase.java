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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.ejbca.webtest.utils.ConfigurationHolder;
import org.ejbca.webtest.utils.ExtentReportCreator;
import org.junit.Rule;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxDriverLogLevel;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.internal.ProfilesIni;

/**
 * Base class to be used by all automated Selenium tests. Should be extended for each test case.
 *
 * @version $Id: WebTestBase.java 30768 2018-12-06 08:06:23Z andrey_s_helmes $
 */
public abstract class WebTestBase extends ExtentReportCreator {

    private static final Logger log = Logger.getLogger(WebTestBase.class);

    private static ConfigurationHolder config;

    private static String ejbcaDomain;
    private static String ejbcaSslPort;
    private static String ejbcaPort;
    private static String downloadDir;
    private static String browserBinary; // null = don't override default
    private static String browserHeadless;
    private static List<WebDriver> webDrivers = new ArrayList<>();

    /**
     * Authentication token to use.
     */
    protected static final AuthenticationToken ADMIN_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    /**
     * Sets up firefox driver and firefox profile if certificate is required.
     * <br/>
     * Corresponds to @BeforeClass annotation in a Test scenario.
     *
     * @param requireCert if certificate is required
     * @param profileConfigProperty browser profile to use. Defined in ConfigurationConstants, null will use default profile.
     */
    public static void beforeClass(final boolean requireCert, final String profileConfigProperty) {
        // Init properties
        setGlobalConstants();
        // Init gecko driver
        config.setGeckoDriver();
        FirefoxOptions firefoxOptions = new FirefoxOptions();
        if (requireCert) {
            final ProfilesIni allProfiles = new ProfilesIni();
            final FirefoxProfile firefoxProfile;
            
            final String configProperty = profileConfigProperty != null ? profileConfigProperty : ConfigurationConstants.PROFILE_FIREFOX_DEFAULT;
            final String profileName = config.getProperty(configProperty);
            if (StringUtils.isEmpty(profileName)) {
                throw new IllegalStateException("Property '" + configProperty + "' must be defined in modules/ejbca-webtest/conf/profiles.properties");
            }
            firefoxProfile = allProfiles.getProfile(profileName);
            
            if (firefoxProfile == null) {
                throw new IllegalStateException("Profile '" + profileName + "' was not found (defined by property '" + configProperty + "').");
            }
            
            firefoxProfile.setAcceptUntrustedCertificates(true);
            firefoxProfile.setPreference("security.default_personal_cert", "Select Automatically");
            firefoxProfile.setPreference("browser.download.folderList", 2);
            firefoxProfile.setPreference("browser.download.dir", downloadDir);
            firefoxProfile.setPreference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream");
            firefoxProfile.setPreference("intl.accept_languages", "en_US, en");
            
            firefoxOptions.setProfile(firefoxProfile);
            firefoxOptions.setLogLevel(FirefoxDriverLogLevel.TRACE);
            firefoxOptions.setAcceptInsecureCerts(true);
        }
        if (browserBinary != null) {
            firefoxOptions.setBinary(browserBinary);
        }
        if (Boolean.parseBoolean(browserHeadless)) {
            firefoxOptions.setHeadless(true);
        }
        
        final WebDriver webDriver = new FirefoxDriver(firefoxOptions);
        webDriver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
        // Add to array
        webDrivers.add(webDriver);
        ExtentReportCreator.setBrowser(getWebDriver());
    }

    /**
     * Closes the firefox drivers.
     * <br/>
     * Corresponds to @AfterClass annotation in a Test scenario.
     */
    public static void afterClass() {
        // Destroy web drivers & close all windows
        if (!webDrivers.isEmpty()) {
            for(WebDriver webDriver : webDrivers) {
                webDriver.quit();
            }
        }
    }

    private static void setGlobalConstants() {
        config = new ConfigurationHolder();
        config.loadAllProperties();
        ejbcaDomain = config.getProperty(ConfigurationConstants.APPSERVER_DOMAIN);
        ejbcaPort = config.getProperty(ConfigurationConstants.APPSERVER_PORT);
        ejbcaSslPort = config.getProperty(ConfigurationConstants.APPSERVER_PORT_SSL);
        downloadDir = config.getProperty(ConfigurationConstants.BROWSER_DOWNLOADDIR);
        browserBinary = config.getProperty(ConfigurationConstants.BROWSER_BINARY);
        browserHeadless = config.getProperty(ConfigurationConstants.BROWSER_HEADLESS);
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

    /**
     * Returns the first WebDriver or null.
     *
     * @return the first WebDriver or null.
     */
    public static WebDriver getWebDriver() {
        if(webDrivers.isEmpty()) {
            return null;
        }
        return webDrivers.get(0);
    }

    /**
     * Returns the last WebDriver or null.
     *
     * @return the last WebDriver or null.
     */
    protected static WebDriver getLastWebDriver() {
        if(webDrivers.isEmpty()) {
            return null;
        }
        return webDrivers.get(webDrivers.size() - 1);
    }

    /**
     * Removes the CA and CryptoToken using EJB instances.
     *
     * @param caName CA name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCaAndCryptoToken(final String caName) {
        removeCaByName(caName);
        removeCryptoTokenByCaName(caName);
    }

    /**
     * Removes the CA using EJB instance.
     *
     * @param caName CA name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCaByName(final String caName) {
        final CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        try {
            final CAInfo caInfo = caSessionRemote.getCAInfo(ADMIN_TOKEN, caName);
            if (caInfo != null) {
                caSessionRemote.removeCA(ADMIN_TOKEN, caInfo.getCAId());
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the CMP alias (configuration) using EJB instance.
     * 
     * @param alias CMP alias to remove
     */
    protected static void removeCmpAliasByName(final String alias) {
        final GlobalConfigurationSessionRemote globalConfigRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        try {
            CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigRemote.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
            cmpConfiguration.removeAlias(alias);
            globalConfigRemote.saveConfiguration(ADMIN_TOKEN, cmpConfiguration);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }
    
    /**
     * Removes the CryptoToken associated with CA using EJB instance.
     *
     * @param caName CA name.
     */
    protected static void removeCryptoTokenByCaName(final String caName) {
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        try {
            final Integer cryptoTokenId = cryptoTokenManagementSessionRemote.getIdFromName(caName);
            if(cryptoTokenId == null) {
                log.error("Cannot remove a crypto token for CA [" + caName + "]");
                return;
            }
            cryptoTokenManagementSessionRemote.deleteCryptoToken(ADMIN_TOKEN, cryptoTokenId);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the CertificateProfile using EJB instance.
     *
     * @param certificateProfileName Certificate profile name.
     */
    protected static void removeCertificateProfileByName(final String certificateProfileName) {
        final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        try {
            certificateProfileSession.removeCertificateProfile(ADMIN_TOKEN, certificateProfileName);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the EndEntityProfile using EJB instance.
     *
     * @param endEntityProfileName End entity profile name.
     */
    protected static void removeEndEntityProfileByName(final String endEntityProfileName) {
        final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        try {
            endEntityProfileSession.removeEndEntityProfile(ADMIN_TOKEN, endEntityProfileName);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the EndEntity using EJB instance, if it exists.
     *
     * @param username username for deletion.
     */
    protected static void removeEndEntityByUsername(final String username) {
        final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        try {
            endEntityManagementSession.deleteUser(ADMIN_TOKEN, username);
        } catch (NoSuchEndEntityException e) {
            // NOPMD This is safe to ignore
        } catch (CouldNotRemoveEndEntityException | AuthorizationDeniedException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Removes the 'Administrator Role' by name using EJB instance.
     *
     * @param roleName role name for deletion.
     */
    protected static void removeAdministratorRoleByName(final String roleName) {
        final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
        try {
            final Role role = roleSession.getRole(ADMIN_TOKEN, null, roleName);
            if (role != null) {
                roleSession.deleteRoleIdempotent(ADMIN_TOKEN, role.getRoleId());
            } else {
                log.error("Cannot remove Administrator Role [" + roleName + "].");
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the 'Approval Profile' by name using EJB instance.
     *
     * @param approvalProfileName approval profile name for deletion.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeApprovalProfileByName(final String approvalProfileName) {
        final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
        try {
            final Map<Integer, String> approvalIdNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
            for (Map.Entry<Integer, String> approvalProfile : approvalIdNameMap.entrySet()) {
                if (approvalProfile.getValue().equals(approvalProfileName)) {
                    approvalProfileSession.removeApprovalProfile(ADMIN_TOKEN, approvalProfile.getKey());
                }
            }
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }
    
    /**
     * Removes the 'Publisher' by its name using EJB remote instance.
     * 
     * @param publisherName name of the publisher to be removed
     * @throws ReferencesToItemExistException exception thrown in case the publisher in use.
     */
    protected static void removePublisherByName(final String publisherName) throws ReferencesToItemExistException {
        final PublisherSessionRemote publisherSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
        try {
            publisherSessionRemote.removePublisher(ADMIN_TOKEN, publisherName);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the 'Approval Request' by its request id using EJB remote instance.
     *
     * @param requestId approval request id.
     */
    protected static void removeApprovalRequestByRequestId(final int requestId) {
        if(requestId != -1) {
            final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
            approvalSession.removeApprovalRequest(ADMIN_TOKEN, requestId);
        }
    }
}
