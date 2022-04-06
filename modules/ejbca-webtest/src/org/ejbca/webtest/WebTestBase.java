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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.SystemTestsConfiguration;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.common.exception.ReferencesToItemExistException;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.validation.CouldNotRemoveKeyValidatorException;
import org.cesecore.keys.validation.KeyValidatorSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.crl.CrlDataTestSessionRemote;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.ejbca.webtest.utils.ConfigurationHolder;
import org.ejbca.webtest.utils.ExtentReportCreator;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.firefox.ProfilesIni;
import org.openqa.selenium.logging.LogType;
import org.openqa.selenium.logging.LoggingPreferences;
import org.openqa.selenium.remote.CapabilityType;

import java.io.File;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;

/**
 * Base class to be used by all automated Selenium tests. Should be extended for each test case.
 * 
 */
public abstract class WebTestBase extends ExtentReportCreator {

    private static final Logger log = Logger.getLogger(WebTestBase.class);
    // Authentication token to use.
    private static final AuthenticationToken ADMIN_TOKEN = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static ConfigurationHolder config;
    // EJBCA
    private static String ejbcaDomain;
    private static String ejbcaPublicPort;
    private static String ejbcaSecurePort;
    // Firefox
    private static String downloadDir;
    private static String browserBinary; // null = don't override default
    private static String browserHeadless;
    private static final List<WebDriver> webDrivers = new ArrayList<>();

    /**
     * Sets up Firefox driver and Firefox profile if certificate is required.
     * <br/>
     * Corresponds to @BeforeClass annotation in a Test scenario.
     *
     * @param requireCert           if certificate is required
     * @param profileConfigProperty browser profile to use. Defined in ConfigurationConstants, null will use default profile.
     */
    protected static void beforeClass(final boolean requireCert, final String profileConfigProperty) {
        // Init properties
        setGlobalConstants();
        // Init gecko driver
        config.setGeckoDriver();
        final FirefoxOptions firefoxOptions = new FirefoxOptions();
        if (requireCert) {
            // Load configuration
            final String configProperty = profileConfigProperty != null ? profileConfigProperty : ConfigurationConstants.PROFILE_FIREFOX_DEFAULT;
            final String profileName = config.getProperty(configProperty);
            if (StringUtils.isEmpty(profileName)) {
                throw new IllegalStateException("Property '" + configProperty + "' must be defined in modules/ejbca-webtest/conf/profiles.properties");
            }
            // Load Firefox profiles
            final ProfilesIni allProfiles = new ProfilesIni();
            final FirefoxProfile firefoxProfile = allProfiles.getProfile(profileName);
            if (firefoxProfile == null) {
                throw new IllegalStateException("Profile '" + profileName + "' was not found (defined by property '" + configProperty + "').");
            }
            // Update Firefox profile's preferences
            firefoxProfile.setAcceptUntrustedCertificates(true);
            firefoxProfile.setPreference("security.default_personal_cert", "Select Automatically");
            firefoxProfile.setPreference("browser.download.folderList", 2);
            firefoxProfile.setPreference("browser.download.useDownloadDir", true);
            firefoxProfile.setPreference("browser.download.dir", downloadDir);
            firefoxProfile.setPreference("browser.helperApps.neverAsk.saveToDisk", "application/pkcs7-mime;application/pkcs12;application/x-pkcs12;application/octet-stream;application/json");
            firefoxProfile.setPreference("browser.download.panel.shown", false);
            firefoxProfile.setPreference("browser.helperApps.alwaysAsk.force", false);
            firefoxProfile.setPreference("browser.download.manager.showWhenStarting",false);
            firefoxProfile.setPreference("browser.download.manager.useWindow", false);
            firefoxProfile.setPreference("browser.download.manager.closeWhenDone", false);
            firefoxProfile.setPreference("intl.accept_languages", "en_US, en");
            // Set profile
            firefoxOptions.setProfile(firefoxProfile);
        }
        if (browserBinary != null) {
            firefoxOptions.setBinary(browserBinary);
        }
        if (Boolean.parseBoolean(browserHeadless)) {
            firefoxOptions.setHeadless(true);
        }
        // Update Firefox options
        firefoxOptions.setAcceptInsecureCerts(true);
        // Logging options, use levels with care, as a change may dramatically affect the size of junit output file.
        final LoggingPreferences loggingPreferences = new LoggingPreferences();
        loggingPreferences.enable(LogType.BROWSER, Level.OFF);
        loggingPreferences.enable(LogType.CLIENT, Level.ALL);
        loggingPreferences.enable(LogType.DRIVER, Level.OFF);
        loggingPreferences.enable(LogType.PERFORMANCE, Level.OFF);
        loggingPreferences.enable(LogType.PROFILER, Level.OFF);
        loggingPreferences.enable(LogType.SERVER, Level.OFF);
        firefoxOptions.setCapability(CapabilityType.LOGGING_PREFS, loggingPreferences);
        //
        final WebDriver webDriver = new FirefoxDriver(firefoxOptions);
        webDriver.manage().timeouts().implicitlyWait(5, TimeUnit.SECONDS);
        // Add to array
        webDrivers.add(webDriver);
        ExtentReportCreator.setBrowser(getWebDriver());
    }

    /**
     * Closes the Firefox drivers.
     * <br/>
     * Corresponds to @AfterClass annotation in a Test scenario.
     */
    protected static void afterClass() {
        // Destroy web drivers & close all windows
        if (!webDrivers.isEmpty()) {
            for (WebDriver webDriver : webDrivers) {
                webDriver.quit();
            }
        }
    }

    private static void setGlobalConstants() {
        config = new ConfigurationHolder();
        config.loadAllProperties();
        ejbcaDomain = config.getProperty(ConfigurationConstants.APPSERVER_DOMAIN);
        ejbcaPublicPort = config.getProperty(ConfigurationConstants.APPSERVER_PORT);
        ejbcaSecurePort = config.getProperty(ConfigurationConstants.APPSERVER_PORT_SSL);
        downloadDir = config.getProperty(ConfigurationConstants.BROWSER_DOWNLOADDIR);
        browserBinary = config.getProperty(ConfigurationConstants.BROWSER_BINARY);
        browserHeadless = config.getProperty(ConfigurationConstants.BROWSER_HEADLESS);
    }

    protected String getCaName() {
        return config.getProperty(ConfigurationConstants.EJBCA_CANAME);
    }

    protected String getCrlUri() {
        return ("http://" + ejbcaDomain + ":" + ejbcaPublicPort + "/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN%3D");
    }

    protected static String getPublicWebUrl() {
        return "http://" + ejbcaDomain + ":" + ejbcaPublicPort + "/ejbca/";
    }

    protected static String getAdminWebUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSecurePort + "/ejbca/adminweb";
    }

    protected static String getBaseUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSecurePort + "/ejbca";
    }

    protected static String getRaWebUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSecurePort + "/ejbca/ra/";
    }
    protected static String getRaWebPublicUrl() {
        return "http://" + ejbcaDomain + ":" + ejbcaPublicPort + "/ejbca/ra/";
    }

    protected static String getSwaggerWebUrl() {
        return "https://" + ejbcaDomain + ":" + ejbcaSecurePort + "/ejbca/swagger-ui#/";
    }

    protected static String getDownloadDir() {
        return downloadDir;
    }

    /**
     * Returns the first WebDriver or null.
     *
     * @return the first WebDriver or null.
     */
    protected static WebDriver getWebDriver() {
        if (webDrivers.isEmpty()) {
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
        if (webDrivers.isEmpty()) {
            return null;
        }
        return webDrivers.get(webDrivers.size() - 1);
    }

    /**
     * Removes the CA and CryptoToken using EJB instances.
     *
     * @param caName CA name.
     */
    protected static void removeCaAndCryptoToken(final String caName) {
        removeCaByName(caName);
        removeCryptoTokenByCaName(caName);
    }

    /**
     * Removes the CA using EJB instance.
     *
     * @param caName CA name.
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
            if (cryptoTokenId == null) {
                log.error("Cannot remove a crypto token for CA [" + caName + "]");
                return;
            }
            cryptoTokenManagementSessionRemote.deleteCryptoToken(ADMIN_TOKEN, cryptoTokenId);
        } catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes the Validator using EJB instance.
     *
     * @param validatorName CA name.
     */
    protected static void removeValidatorByName(final String validatorName) {
        final KeyValidatorSessionRemote validatorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyValidatorSessionRemote.class);
        try {
            validatorSession.removeKeyValidator(ADMIN_TOKEN, validatorName);
        } catch (AuthorizationDeniedException | CouldNotRemoveKeyValidatorException e) {
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
     * Removes the Certificate using EJB instance.
     *
     * @param username Certificate profile name.
     */
    protected static void removeCertificateByUsername(final String username) {
        final InternalCertificateStoreSessionRemote certificateStoreSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
         certificateStoreSessionRemote.removeCertificatesByUsername(username);
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
        if (requestId != -1) {
            final ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
            approvalSession.removeApprovalRequest(ADMIN_TOKEN, requestId);
        }
    }

    protected static void removeServiceByName(final String serviceName) {
        final ServiceSessionRemote serviceSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        try {
            serviceSessionRemote.removeService(ADMIN_TOKEN, serviceName);
        } catch (Exception e) {
            throw new IllegalStateException(e); //Should never happen with always allow token
        }
    }

    protected static void removeCrlByIssuerDn(final String issuerDn) {
        final CrlDataTestSessionRemote crlDataTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlDataTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
        try {
            crlDataTestSession.deleteCrlDataByIssuerDn(issuerDn);
        } catch (Exception e) {
            throw new IllegalStateException(e); //Should never happen with always allow token
        }
    }

    /**
     * Deletes a file in the download directory. Does nothing if the file does not exist.
     *
     * @param filename File name, relative to the download directory.
     */
    protected static void deleteDownloadedFile(final String filename) {
        final File file = new File(getDownloadDir(), filename);
        if (file.exists()) {
            if (!file.delete()) {
                log.warn("Failed to delete downloaded file: " + file);
            }
        }
    }

    protected static Collection<CertificateWrapper> findSerialNumber(final String username) {
        final CertificateStoreSessionRemote certificateDataSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        try {
            return certificateDataSession.findCertificatesByUsername(username);
        } catch (Exception e) {
            throw new IllegalStateException(e); //Should never happen with always allow token
        }

    }

    /**
     * Finds the name of the crypto token for the management CA. Defaults to "ManagementCA" if something goes wrong.
     */
    protected static String getManagementCACryptoTokenName() {
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        for (final String caName : SystemTestsConfiguration.getClientCertificateCaNames()) {
            try {
                final CAInfo managementCa = caSession.getCAInfo(ADMIN_TOKEN, caName);
                if (managementCa.getCAToken() != null) {
                    final int cryptoTokenId = managementCa.getCAToken().getCryptoTokenId();
                    final CryptoTokenInfo cryptoToken = cryptoTokenManagementSession.getCryptoTokenInfo(ADMIN_TOKEN, cryptoTokenId);
                    if (cryptoToken != null) {
                        return cryptoToken.getName();
                    }
                } else {
                    log.error("CA '" + managementCa.getName() + "' exists, but has no Crypto Token");
                }
            } catch (AuthorizationDeniedException e) {
                log.error("Authorization denied to CA '" + caName + "': " + e.getMessage(), e);
            }
        }
        return "ManagementCA";
    }

    /**
     * Removes CT Log parameters
     * @param ctLogParameters an array of CT Log parameters.
     */
    protected static void removeCertificateTransparencyLogs(String... ctLogParameters) {
        final GlobalConfigurationSessionRemote globalConfigurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSessionRemote
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final LinkedHashMap<Integer, CTLogInfo> ctLogs = globalConfiguration.getCTLogs();
        ctLogs.forEach((key, ctLogInfo) -> {
            if (Arrays.asList(ctLogParameters).contains(ctLogInfo.getUrl())) {
                globalConfiguration.removeCTLog(ctLogInfo.getLogId());
            }
        });
        try {
            globalConfigurationSessionRemote.saveConfiguration(ADMIN_TOKEN, globalConfiguration);
        }
        catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }

    /**
     * Removes OAuth Providers
     * @param oauthKeyIdentifiers an array of OAuth Provider Key Identifiers.
     */
    protected static void removeOauthProviders(String... oauthKeyIdentifiers) {
        final GlobalConfigurationSessionRemote globalConfigurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        final OAuthConfiguration oAuthConfiguration = (OAuthConfiguration) globalConfigurationSessionRemote
                .getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        final Map<String, OAuthKeyInfo> oauthKeys = oAuthConfiguration.getOauthKeys();
        oauthKeys.forEach((key, oauthKeyInfo) -> {
            if (Arrays.asList(oauthKeyIdentifiers).contains(oauthKeyInfo.getLabel())) {
                oAuthConfiguration.removeOauthKey(oauthKeyInfo.getLabel());
            }
        });
        try {
            globalConfigurationSessionRemote.saveConfiguration(ADMIN_TOKEN, oAuthConfiguration);
        }
        catch (AuthorizationDeniedException e) {
            throw new IllegalStateException(e); // Should never happen with always allow token
        }
    }
}
