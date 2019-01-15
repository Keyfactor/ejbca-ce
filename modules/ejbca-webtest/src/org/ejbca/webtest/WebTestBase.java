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
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
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
 * @version $Id: WebTestBase.java 30768 2018-12-06 08:06:23Z andrey_s_helmes $
 */
public abstract class WebTestBase {

    private static final Logger log = Logger.getLogger(WebTestBase.class);

    private static ConfigurationHolder config;

    private static String ejbcaDomain;
    private static String ejbcaSslPort;
    private static String ejbcaPort;
    private static String downloadDir;
    private static String browserBinary; // null = don't override default
    private static String browserHeadless;
    private static String profilePath;
    private static WebDriver webDriver;
    private static WebDriverWait webDriverWait;

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
            firefoxOptions.setProfile(firefoxProfile);

            firefoxOptions.setAcceptInsecureCerts(true);
        }
        if (browserBinary != null) {
            firefoxOptions.setBinary(browserBinary);
        }
        if (Boolean.parseBoolean(browserHeadless)) {
            firefoxOptions.setHeadless(true);
        }
        
        /*
        if (profilePath != null) {
            firefoxOptions.addArguments("-profile", profilePath);
            firefoxOptions.setLogLevel(FirefoxDriverLogLevel.TRACE);
        }
        */
        
        webDriver = new FirefoxDriver(firefoxOptions);

        webDriver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
        webDriverWait = new WebDriverWait(webDriver, 5, 50);
    }

    /**
     * Closes the firefox driver.
     * <br/>
     * Corresponds to @AfterClass annotation in a Test scenario.
     */
    public static void afterClass() {
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
        browserBinary = config.getProperty(ConfigurationConstants.BROWSER_BINARY);
        browserHeadless = config.getProperty(ConfigurationConstants.BROWSER_HEADLESS);
        profilePath = config.getProperty(ConfigurationConstants.BROWSER_PROFILEPATH);
        
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

    /**
     * Removes the CA and CryptoToken using EJB instances.
     *
     * @param caName CA name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCaAndCryptoToken(final String caName) throws AuthorizationDeniedException {
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
    protected static void removeCaByName(final String caName) throws AuthorizationDeniedException {
        final CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final CAInfo caInfo = caSessionRemote.getCAInfo(ADMIN_TOKEN, caName);
        if(caInfo != null) {
            caSessionRemote.removeCA(ADMIN_TOKEN, caInfo.getCAId());
        }
    }

    /**
     * Removes the CMP alias (configuration) using EJB instance.
     * 
     * @param alias CMP alias to remove
     * 
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCmpAliasByName(final String alias) throws AuthorizationDeniedException {
        final GlobalConfigurationSessionRemote globalConfigRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        CmpConfiguration cmpConfiguration = (CmpConfiguration) globalConfigRemote.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        cmpConfiguration.removeAlias(alias);
        globalConfigRemote.saveConfiguration(ADMIN_TOKEN, cmpConfiguration);
    }
    
    /**
     * Removes the CryptoToken associated with CA using EJB instance.
     *
     * @param caName CA name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCryptoTokenByCaName(final String caName) throws AuthorizationDeniedException {
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final Integer cryptoTokenId = cryptoTokenManagementSessionRemote.getIdFromName(caName);
        if(cryptoTokenId == null) {
            log.error("Cannot remove a crypto token for CA [" + caName + "]");
            return;
        }
        cryptoTokenManagementSessionRemote.deleteCryptoToken(ADMIN_TOKEN, cryptoTokenId);
    }

    /**
     * Removes the CertificateProfile using EJB instance.
     *
     * @param certificateProfileName Certificate profile name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeCertificateProfileByName(final String certificateProfileName) throws AuthorizationDeniedException {
        final CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        certificateProfileSession.removeCertificateProfile(ADMIN_TOKEN, certificateProfileName);
    }

    /**
     * Removes the EndEntityProfile using EJB instance.
     *
     * @param endEntityProfileName End entity profile name.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeEndEntityProfileByName(final String endEntityProfileName) throws AuthorizationDeniedException {
        final EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        endEntityProfileSession.removeEndEntityProfile(ADMIN_TOKEN, endEntityProfileName);
    }

    /**
     * Removes the EndEntity using EJB instance.
     *
     * @param username username for deletion.
     *
     * @throws CouldNotRemoveEndEntityException in case of referencing objects.
     * @throws NoSuchEndEntityException in case of non-existing end entity.
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeEndEntityByUsername(final String username) throws CouldNotRemoveEndEntityException, NoSuchEndEntityException, AuthorizationDeniedException {
        final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        endEntityManagementSession.deleteUser(ADMIN_TOKEN, username);
    }

    /**
     * Removes the 'Administrator Role' by name using EJB instance.
     *
     * @param roleName role name for deletion.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeAdministratorRoleByName(final String roleName) throws AuthorizationDeniedException {
        final RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
        final Role role = roleSession.getRole(ADMIN_TOKEN, null, roleName);
        if(role != null) {
            roleSession.deleteRoleIdempotent(ADMIN_TOKEN, role.getRoleId());
        }
        else {
            log.error("Cannot remove Administrator Role [" + roleName + "].");
        }
    }

    /**
     * Removes the 'Approval Profile' by name using EJB instance.
     *
     * @param approvalProfileName approval profile name for deletion.
     *
     * @throws AuthorizationDeniedException in case of authorization problem.
     */
    protected static void removeApprovalProfileByName(final String approvalProfileName) throws AuthorizationDeniedException {
        final ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
        final Map<Integer, String> approvalIdNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (Map.Entry<Integer, String> approvalProfile : approvalIdNameMap.entrySet()) {
            if (approvalProfile.getValue().equals(approvalProfileName)) {
                approvalProfileSession.removeApprovalProfile(ADMIN_TOKEN, approvalProfile.getKey());
            }
        }
    }
    
    /**
     * Removes the 'Publisher' by its name using EJB remote instance.
     * 
     * @param publisherName name of the publisher to be removed
     * @throws ReferencesToItemExistException exception thrown in case the publisher in use.
     * @throws AuthorizationDeniedException exception thrown in case of authorization problem.
     */
    protected static void removePublisherByName(final String publisherName) throws ReferencesToItemExistException, AuthorizationDeniedException {
        final PublisherSessionRemote publisherSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
        publisherSessionRemote.removePublisher(ADMIN_TOKEN, publisherName);
    }
}
