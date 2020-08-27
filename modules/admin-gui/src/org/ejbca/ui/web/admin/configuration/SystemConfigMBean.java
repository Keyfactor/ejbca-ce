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
package org.ejbca.ui.web.admin.configuration;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.certificatetransparency.GoogleCtPolicy;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.InvalidConfigurationException;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.config.RaStyleInfo.RaCssInfo;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.util.FileTools;
import org.cesecore.util.SecureZipUnpacker;
import org.cesecore.util.StreamSizeLimitExceededException;
import org.ejbca.config.AvailableProtocolsConfiguration;
import org.ejbca.config.AvailableProtocolsConfiguration.AvailableProtocols;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.GlobalCustomCssConfiguration;
import org.ejbca.core.ejb.ocsp.OcspResponseCleanupSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.statedump.ejb.StatedumpImportOptions;
import org.ejbca.statedump.ejb.StatedumpImportResult;
import org.ejbca.statedump.ejb.StatedumpObjectKey;
import org.ejbca.statedump.ejb.StatedumpResolution;
import org.ejbca.statedump.ejb.StatedumpSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.configuration.WebLanguage;
import org.ejbca.ui.web.configuration.exception.CacheClearException;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Backing bean for the various system configuration pages.
 *
 * @version $Id$
 */
@ManagedBean
@SessionScoped
public class SystemConfigMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -6653610614851741905L;
    private static final Logger log = Logger.getLogger(SystemConfigMBean.class);

    public class GuiInfo {
        private String title;
        private String headBanner;
        private String footBanner;
        private boolean enableEndEntityProfileLimitations;
        private boolean enableKeyRecovery;
        private boolean localKeyRecovery;
        private int localKeyRecoveryCryptoTokenId;
        private String localKeyRecoveryKeyAlias;
        private boolean enableIcaoCANameChange;
        private boolean issueHardwareToken;
        private boolean useAutoEnrollment;
        private int autoEnrollmentCA;
        private boolean autoEnrollUseSSLConnection;
        private String autoEnrollAdServer;
        private int autoEnrollAdServerPort;
        private String autoEnrollConnectionDN;
        private String autoEnrollUserBaseDN;
        private String autoEnrollConnectionPassword;
        private Set<String> nodesInCluster;
        private boolean enableCommandLine;
        private boolean enableCommandLineDefaultUser;
        private boolean enableExternalScripts;
        private List<CTLogInfo> ctLogs;
        private boolean publicWebCertChainOrderRootFirst;
        private boolean enableSessionTimeout;
        private int sessionTimeoutTime;

        // Settings for the cleanup job for removing old OCSP responses created by the presigners.
        private boolean ocspCleanupUse;
        private String ocspCleanupSchedule;
        private String ocspCleanupScheduleUnit;

        //Admin Preferences
        private int preferedLanguage;
        private int secondaryLanguage;
        private String theme;
        private int entriesPerPage;

        //Database preferences
        private int maximumQueryCount;
        private long maximumQueryTimeout;

        private GuiInfo(GlobalConfiguration globalConfig, GlobalCesecoreConfiguration globalCesecoreConfiguration, AdminPreference adminPreference) {
            if(globalConfig == null) {
                globalConfig = getEjbcaWebBean().getGlobalConfiguration();
            }

            try {
                this.title = globalConfig.getEjbcaTitle();
                this.headBanner = globalConfig.getHeadBanner();
                this.footBanner = globalConfig.getFootBanner();
                this.enableEndEntityProfileLimitations = globalConfig.getEnableEndEntityProfileLimitations();
                this.enableKeyRecovery = globalConfig.getEnableKeyRecovery();
                this.localKeyRecovery = globalConfig.getLocalKeyRecovery();
                this.localKeyRecoveryCryptoTokenId = globalConfig.getLocalKeyRecoveryCryptoTokenId() != null ? globalConfig.getLocalKeyRecoveryCryptoTokenId() : 0;
                this.localKeyRecoveryKeyAlias = globalConfig.getLocalKeyRecoveryKeyAlias();
                this.useAutoEnrollment = globalConfig.getAutoEnrollUse();
                this.autoEnrollmentCA = globalConfig.getAutoEnrollCA();
                this.autoEnrollUseSSLConnection = globalConfig.getAutoEnrollSSLConnection();
                this.autoEnrollAdServer = globalConfig.getAutoEnrollADServer();
                this.autoEnrollAdServerPort = globalConfig.getAutoEnrollADPort();
                this.autoEnrollConnectionDN = globalConfig.getAutoEnrollConnectionDN();
                this.autoEnrollUserBaseDN = globalConfig.getAutoEnrollBaseDNUser();
                this.autoEnrollConnectionPassword = globalConfig.getAutoEnrollConnectionPwd();
                this.nodesInCluster = globalConfig.getNodesInCluster();
                this.enableCommandLine = globalConfig.getEnableCommandLineInterface();
                this.enableCommandLineDefaultUser = globalConfig.getEnableCommandLineInterfaceDefaultUser();
                this.enableExternalScripts = globalConfig.getEnableExternalScripts();
                this.publicWebCertChainOrderRootFirst = globalConfig.getPublicWebCertChainOrderRootFirst();
                this.enableSessionTimeout = globalConfig.getUseSessionTimeout();
                this.sessionTimeoutTime = globalConfig.getSessionTimeoutTime();
                this.setEnableIcaoCANameChange(globalConfig.getEnableIcaoCANameChange());
                this.ctLogs = new ArrayList<>(globalConfig.getCTLogs().values());
                this.ocspCleanupUse = globalConfig.getOcspCleanupUse();
                this.ocspCleanupSchedule = globalConfig.getOcspCleanupSchedule();
                this.ocspCleanupScheduleUnit = globalConfig.getOcspCleanupScheduleUnit();

                // Admin Preferences
                if(adminPreference == null) {
                    adminPreference = getEjbcaWebBean().getAdminPreference();
                }
                this.preferedLanguage = adminPreference.getPreferedLanguage();
                this.secondaryLanguage = adminPreference.getSecondaryLanguage();
                this.theme = adminPreference.getTheme();
                this.entriesPerPage = adminPreference.getEntriesPerPage();

                this.maximumQueryCount = globalCesecoreConfiguration.getMaximumQueryCount();
                this.maximumQueryTimeout= globalCesecoreConfiguration.getMaximumQueryTimeout();
            } catch (RuntimeException e) {
                log.error(e.getMessage(), e);
            }
        }

        public String getTitle() { return this.title; }
        public void setTitle(String title) { this.title=title; }
        public String getHeadBanner() { return this.headBanner; }
        public void setHeadBanner(String banner) { this.headBanner=banner; }
        public String getFootBanner() { return this.footBanner; }
        public void setFootBanner(String banner) { this.footBanner=banner; }
        public boolean getEnableEndEntityProfileLimitations() { return this.enableEndEntityProfileLimitations; }
        public void setEnableEndEntityProfileLimitations(boolean enableLimitations) { this.enableEndEntityProfileLimitations=enableLimitations; }
        public boolean getEnableKeyRecovery() { return this.enableKeyRecovery; }
        public void setEnableKeyRecovery(boolean enableKeyRecovery) { this.enableKeyRecovery=enableKeyRecovery; }
        public boolean getLocalKeyRecovery() { return this.localKeyRecovery; }
        public void setLocalKeyRecovery(boolean localKeyRecovery) { this.localKeyRecovery=localKeyRecovery; }
        public int getLocalKeyRecoveryCryptoTokenId() { return this.localKeyRecoveryCryptoTokenId; }
        public void setLocalKeyRecoveryCryptoTokenId(int localKeyRecoveryCryptoTokenId) { this.localKeyRecoveryCryptoTokenId=localKeyRecoveryCryptoTokenId; }
        public String getLocalKeyRecoveryKeyAlias() { return this.localKeyRecoveryKeyAlias; }
        public void setLocalKeyRecoveryKeyAlias(String localKeyRecoveryKeyAlias) { this.localKeyRecoveryKeyAlias=localKeyRecoveryKeyAlias; }
        public boolean getIssueHardwareToken() { return this.issueHardwareToken; }
        public void setIssueHardwareToken(boolean issueHWtoken) { this.issueHardwareToken=issueHWtoken; }
        public boolean getUseAutoEnrollment() { return this.useAutoEnrollment; }
        public void setUseAutoEnrollment(boolean useAutoEnrollment) { this.useAutoEnrollment=useAutoEnrollment; }
        public int getAutoEnrollmentCA() { return this.autoEnrollmentCA; }
        public void setAutoEnrollmentCA(int caid) {this.autoEnrollmentCA=caid; }
        public boolean getAutoEnrollUseSSLConnection() { return autoEnrollUseSSLConnection; }
        public void setAutoEnrollUseSSLConnection(boolean useSSLConnection) { this.autoEnrollUseSSLConnection=useSSLConnection; }
        public String getAutoEnrollAdServer() { return this.autoEnrollAdServer; }
        public void setAutoEnrollAdServer(String server) { this.autoEnrollAdServer=server; }
        public int getAutoEnrollAdServerPort() { return this.autoEnrollAdServerPort; }
        public void setAutoEnrollAdServerPort(int port) { this.autoEnrollAdServerPort=port; }
        public String getAutoEnrollConnectionDN() { return this.autoEnrollConnectionDN; }
        public void setAutoEnrollConnectionDN(String dn) { this.autoEnrollConnectionDN=dn; }
        public String getAutoEnrollUserBaseDN() { return this.autoEnrollUserBaseDN; }
        public void setAutoEnrollUserBaseDN(String dn) { this.autoEnrollUserBaseDN=dn; }
        public String getAutoEnrollConnectionPassword() { return this.autoEnrollConnectionPassword; }
        public void setAutoEnrollConnectionPassword(String password) { this.autoEnrollConnectionPassword=password; }
        public Set<String> getNodesInCluster() { return this.nodesInCluster; }
        public void setNodesInCluster(Set<String> nodes) { this.nodesInCluster=nodes; }
        public boolean getEnableCommandLine() { return this.enableCommandLine; }
        public void setEnableCommandLine(boolean enableCommandLine) { this.enableCommandLine=enableCommandLine; }
        public boolean getEnableCommandLineDefaultUser() { return this.enableCommandLineDefaultUser; }
        public void setEnableCommandLineDefaultUser(boolean enableCommandLineDefaultUser) { this.enableCommandLineDefaultUser=enableCommandLineDefaultUser; }
        public boolean getEnableExternalScripts() { return this.enableExternalScripts; }
        public void setEnableExternalScripts(boolean enableExternalScripts) { this.enableExternalScripts=enableExternalScripts; }
        public List<CTLogInfo> getCtLogs() {return this.ctLogs; }
        public void setCtLogs(List<CTLogInfo> ctlogs) { this.ctLogs=ctlogs; }
        public boolean getPublicWebCertChainOrderRootFirst() { return this.publicWebCertChainOrderRootFirst; }
        public void setPublicWebCertChainOrderRootFirst(boolean publicWebCertChainOrderRootFirst) { this.publicWebCertChainOrderRootFirst=publicWebCertChainOrderRootFirst; }
        public boolean isEnableSessionTimeout() { return enableSessionTimeout; }
        public void setEnableSessionTimeout(boolean enableSessionTimeout) { this.enableSessionTimeout = enableSessionTimeout;}
        public int getSessionTimeoutTime() {return sessionTimeoutTime;}
        public void setSessionTimeoutTime(int sessionTimeoutTime) {this.sessionTimeoutTime = sessionTimeoutTime;}

        public boolean getEnableIcaoCANameChange() {return enableIcaoCANameChange;}
        public void setEnableIcaoCANameChange(boolean enableIcaoCANameChange) {this.enableIcaoCANameChange = enableIcaoCANameChange;}

        // OCSP Options: Cleanup Job
        public boolean getOcspCleanupUse() { return ocspCleanupUse; }
        public void setOcspCleanupUse(final boolean value) { this.ocspCleanupUse = value; }

        public String getOcspCleanupSchedule() { return ocspCleanupSchedule; }
        public void setOcspCleanupSchedule(final String value) {this.ocspCleanupSchedule = value;}

        public String getOcspCleanupScheduleUnit() { return ocspCleanupScheduleUnit; }
        public void setOcspCleanupScheduleUnit(final String value) {this.ocspCleanupScheduleUnit = value;}

        // Admin Preferences
        public int getPreferedLanguage() { return this.preferedLanguage; }
        public void setPreferedLanguage(int preferedLanguage) { this.preferedLanguage=preferedLanguage; }
        public int getSecondaryLanguage() { return this.secondaryLanguage; }
        public void setSecondaryLanguage(int secondaryLanguage) { this.secondaryLanguage=secondaryLanguage; }
        public String getTheme() { return this.theme; }
        public void setTheme(String theme) { this.theme=theme; }
        public int getEntriesPerPage() { return this.entriesPerPage; }
        public void setEntriesPerPage(int entriesPerPage) { this.entriesPerPage=entriesPerPage; }

        public int getMaximumQueryCount() { return maximumQueryCount; }
        public void setMaximumQueryCount(int maximumQueryCount) { this.maximumQueryCount = maximumQueryCount; }
        public long getMaximumQueryTimeout() { return maximumQueryTimeout; }
        public void setMaximumQueryTimeout(final long maximumQueryTimeout) { this.maximumQueryTimeout = maximumQueryTimeout; }
    }

    public class EKUInfo {
        private String oid;
        private String name;
        private EKUInfo(String oid, String name) {
            this.oid = oid;
            this.name = name;
        }
        public String getOid() { return this.oid; }
        public void  setOid(String oid) { this.oid=oid; }
        public String getName() { return this.name; }
        public void setName(String name) { this.name=name; }
    }

    public class CustomCertExtensionInfo {
        private int id;
        private String oid;
        private String displayName;
        private boolean critical;
        private boolean required;
        private String encoding;

        public CustomCertExtensionInfo(CertificateExtension extension) {
            this.id = extension.getId();
            this.oid = extension.getOID();
            this.displayName = getEjbcaWebBean().getText(extension.getDisplayName());
            this.critical = extension.isCriticalFlag();
            this.required = extension.isRequiredFlag();
            Properties props = extension.getProperties();
            this.encoding = props.getProperty("encoding", "");
        }
        public int getId() { return this.id; }
        public void setId(int id) { this.id=id; }
        public String getOid() { return this.oid; }
        public void setOid(String oid) { this.oid=oid; }
        public String getDisplayName() { return this.displayName; }
        public void setDisplayName(String displayName) { this.displayName=displayName; }
        public boolean isCritical() { return this.critical; }
        public boolean isRequired() { return this.required; }
        public String getEncoding() { return this.encoding; }
    }

    private String selectedTab = null;
    private GlobalConfiguration globalConfig = null;
    private GlobalCesecoreConfiguration globalCesecoreConfiguration = null;
    private AdminPreference adminPreference = null;
    private GuiInfo currentConfig = null;
    private ValidatorSettings validatorSettings;
    private List<SelectItem> availableCryptoTokens;
    private List<SelectItem> availableKeyAliases;
    private ListDataModel<String> nodesInCluster = null;
    private String currentNode = null;
    private boolean excludeActiveCryptoTokensFromClearCaches = true;
    private boolean customCertificateExtensionViewMode = false;
    private UploadedFile statedumpFile = null;
    private String statedumpDir = null;
    private boolean statedumpLockdownAfterImport = false;
    private SystemConfigurationCtLogManager ctLogManager;
    private GoogleCtPolicy googleCtPolicy;

    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final CertificateProfileSessionLocal certificateProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final CryptoTokenManagementSessionLocal cryptoTokenManagementSession = getEjbcaWebBean().getEjb().getCryptoTokenManagementSession();
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    /** Session bean for importing statedump. Will be null if statedump isn't available */
    private final StatedumpSessionLocal statedumpSession = new EjbLocalHelper().getStatedumpSession();
    private final RoleDataSessionLocal roleSession = getEjbcaWebBean().getEjb().getRoleDataSession();
    private final OcspResponseCleanupSessionLocal ocspCleanupSession = getEjbcaWebBean().getEjb().getOcspResponseCleanupSession();

    public void authorizeViewCt(ComponentSystemEvent event) throws Exception {
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource());
        } else if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
    }

    public void authorizeViewCertExtension(ComponentSystemEvent event) throws Exception {
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            getEjbcaWebBean().initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource());
        } else if (!getEjbcaWebBean().isAuthorizedNoLogSilent(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource())) {
            throw new AuthorizationDeniedException("You are not authorized to view this page.");
        }
    }

    public SystemConfigMBean() throws AuthorizationDeniedException {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR);
        if (!authorizationSession.isAuthorized(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource()) &&
                !authorizationSession.isAuthorized(getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource()) &&
                !authorizationSession.isAuthorized(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource())) {
            throw new AuthorizationDeniedException("Administrator was not authorized to any configuration.");
        }
    }

    /**
     * Get an object which can be used to manage the CT log configuration. This will create a new CT log manager for
     * the CT logs in the current configuration if no CT log manager has been created, or the old CT log manager
     * was flushed.
     * @return the CT log manager for this bean
     */
    public SystemConfigurationCtLogManager getCtLogManager() {
        if (ctLogManager == null) {
            ctLogManager = new SystemConfigurationCtLogManager(getCurrentConfig().getCtLogs(),
                new SystemConfigurationCtLogManager.SystemConfigurationHelper() {
                    @Override
                    public void saveCtLogs(final List<CTLogInfo> ctLogs) {
                        getCurrentConfig().setCtLogs(ctLogs);
                        saveCurrentConfig();
                    }

                    @Override
                    public void addInfoMessage(final String languageKey) {
                        SystemConfigMBean.this.addInfoMessage(languageKey);
                    }

                    @Override
                    public void addErrorMessage(final String languageKey, final Object... params) {
                        SystemConfigMBean.this.addErrorMessage(languageKey, params);
                    }

                    @Override
                    public void addErrorMessage(final String languageKey) {
                        SystemConfigMBean.this.addErrorMessage(languageKey);
                    }

                    @Override
                    public List<String> getCertificateProfileNamesByCtLog(final CTLogInfo ctLog) {
                        final List<String> usedByProfiles = new ArrayList<>();
                        final Map<Integer, String> idToName = certificateProfileSession.getCertificateProfileIdToNameMap();
                        for (Entry<Integer, CertificateProfile> entry : certificateProfileSession.getAllCertificateProfiles().entrySet()) {
                            final int certificateProfileId = entry.getKey();
                            final CertificateProfile certificateProfile = entry.getValue();
                            if (certificateProfile.getEnabledCtLabels().contains(ctLog.getLabel())) {
                                usedByProfiles.add(idToName.get(certificateProfileId));
                            }
                        }
                        return usedByProfiles;
                    }
                });
        }
        return ctLogManager;
    }

    public GoogleCtPolicy getGoogleCtPolicy() {
        if (googleCtPolicy == null) {
            googleCtPolicy = getGlobalConfiguration().getGoogleCtPolicy();
        }
        return googleCtPolicy;
    }

    public GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
        if (globalCesecoreConfiguration == null) {
            globalCesecoreConfiguration = (GlobalCesecoreConfiguration) getEjbcaWebBean().getEjb().getGlobalConfigurationSession()
                    .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        }
        return globalCesecoreConfiguration;
    }

    public GlobalConfiguration getGlobalConfiguration() {
        if(globalConfig == null) {
            globalConfig = getEjbcaWebBean().getGlobalConfiguration();
        }
        return globalConfig;
    }

    public AdminPreference getAdminPreference() throws Exception {
        if(adminPreference == null) {
            adminPreference = getEjbcaWebBean().getDefaultAdminPreference();
        }
        return adminPreference;
    }

    /** @return cached or populate a new system configuration GUI representation for view or edit */
    public GuiInfo getCurrentConfig() {
        if(this.currentConfig == null) {
            try {
                this.currentConfig = new GuiInfo(getGlobalConfiguration(), getGlobalCesecoreConfiguration(), getAdminPreference());
            } catch (Exception e) {
                String msg = "Cannot read Administrator Preferences.";
                log.info(msg + e.getLocalizedMessage());
                super.addNonTranslatedErrorMessage(msg);
            }
        }
        return this.currentConfig;
    }

    /** @return current settings for the Validators tab */
    public ValidatorSettings getValidatorSettings() {
        if (validatorSettings == null) {
            validatorSettings = new ValidatorSettings(new ValidatorSettings.ValidatorSettingsHelper() {
                @Override
                public GlobalConfiguration getGlobalConfiguration() {
                    return SystemConfigMBean.this.getGlobalConfiguration();
                }

                @Override
                public void addErrorMessage(final String languageKey, final Object... params) {
                    SystemConfigMBean.this.addErrorMessage(languageKey, params);
                }

                @Override
                public void addInfoMessage(final String languageKey) {
                    SystemConfigMBean.this.addInfoMessage(languageKey);
                }

                @Override
                public void persistConfiguration(final GlobalConfiguration globalConfiguration) throws AuthorizationDeniedException {
                    getEjbcaWebBean().saveGlobalConfiguration(globalConfiguration);
                }
            });
        }
        return validatorSettings;
    }

    public String getSelectedTab() {
        final String tabHttpParam = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("tab");
        // First, check if the user has requested a valid tab
        List<String> availableTabs = getAvailableTabs();
        if (tabHttpParam != null && availableTabs.contains(tabHttpParam)) {
            // The requested tab is an existing tab. Flush caches so we reload the page content
            flushCache();
            selectedTab = tabHttpParam;
        }
        if (selectedTab == null) {
            // If no tab was requested, we use the first available tab as default
            selectedTab = availableTabs.get(0);
        }
        return selectedTab;
    }

    public String getCurrentNode() {
        return this.currentNode;
    }
    public void setCurrentNode(String node) {
        this.currentNode = node;
    }

    public boolean getExcludeActiveCryptoTokensFromClearCaches() {
        return this.excludeActiveCryptoTokensFromClearCaches;
    }
    public void setExcludeActiveCryptoTokensFromClearCaches(boolean exclude) {
        this.excludeActiveCryptoTokensFromClearCaches = exclude;
    }
    public void clearAllCaches() {
        boolean execludeActiveCryptoTokens = getExcludeActiveCryptoTokensFromClearCaches();
        try {
            getEjbcaWebBean().clearClusterCache(execludeActiveCryptoTokens);
        } catch (CacheClearException e) {
            String msg = "Cannot clear caches: " + e.getLocalizedMessage();
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    public String getStatedumpDir() {
        return statedumpDir;
    }

    public void setStatedumpDir(final String statedumpDir) {
        this.statedumpDir = statedumpDir;
    }

    public UploadedFile getStatedumpFile() {
        return statedumpFile;
    }

    public void setStatedumpFile(final UploadedFile statedumpFile) {
        this.statedumpFile = statedumpFile;
    }

    public boolean getStatedumpLockdownAfterImport() {
        return statedumpLockdownAfterImport;
    }

    public void setStatedumpLockdownAfterImport(final boolean statedumpLockdownAfterImport) {
        this.statedumpLockdownAfterImport = statedumpLockdownAfterImport;
    }

    /** Returns true if EJBCA was built with Statedump (from EJBCA 6.5.0 or later) and it hasn't been locked down in the user interface. */
    public boolean isStatedumpAvailable() {
        return statedumpSession != null && !getGlobalConfiguration().getStatedumpLockedDown();
    }

    public List<SelectItem> getStatedumpAvailableTemplates() {
        final List<SelectItem> templates = new ArrayList<>();
        try {
            for (Map.Entry<String,String> entry : statedumpSession.getAvailableTemplates(getAdmin()).entrySet()) {
                final String description = getEjbcaWebBean().getText(entry.getValue());
                templates.add(new SelectItem(entry.getKey(), description));
            }
        } catch (AuthorizationDeniedException e) {
            log.debug("Authorization was denied to list statedump templates");
        }
        sortSelectItemsByLabel(templates);
        templates.add(0, new SelectItem("", getEjbcaWebBean().getText("NONE")));
        return templates;
    }

    public boolean isStatedumpTemplatesVisible() {
        try {
            final String basedir = statedumpSession.getTemplatesBasedir(getAdmin());
            return basedir != null && !basedir.isEmpty() && new File(basedir).isDirectory();
        } catch (AuthorizationDeniedException e) {
            return false;
        }
    }

    private void importStatedump(final File path, final boolean lockdown) throws IOException, AuthorizationDeniedException {
        final StatedumpImportOptions options = new StatedumpImportOptions();
        options.setLocation(path);
        // Since we currently don't give the user any option to upload an overrides file, we look for an overrides file in the .zip file
        options.setOverridesFile(new File(path, "overrides.properties"));
        options.setMergeCryptoTokens(true);

        StatedumpImportResult result = statedumpSession.performDryRun(getAdmin(), options);
        for (final StatedumpObjectKey key : result.getConflicts()) {
            log.info("Will overwrite "+key);
            options.addConflictResolution(key, StatedumpResolution.OVERWRITE);
        }
        for (final StatedumpObjectKey key : result.getPasswordsNeeded()) {
            log.info("Will use dummy 'foo123' password for "+key+", please disable or change it!");
            options.addPassword(key, "foo123");
        }

        log.info("Performing statedump import");
        result = statedumpSession.performImport(getAdmin(), options);
        log.info("Statedump was successfully imported.");

        // Lock down after import
        if (lockdown) {
            log.info("Locking down Statedump in the CA web.");
            lockDownStatedump();
        } else {
            log.debug("Not locking down Statedump.");
        }

        // Done, add result messages
        for (String msg : result.getNotices()) {
            super.addNonTranslatedInfoMessage(msg);
        }
    }

    private void importStatedump(byte[] zip, boolean lockdown) throws IOException, AuthorizationDeniedException {
        // Check that it's a ZIP file
        if (!FileTools.isZipFile(zip)) {
            throw new IOException("File is not a valid zip file.");
        }

        // Create temporary directory
        final Path tempdirPath = Files.createTempDirectory("ejbca_statedump_gui");
        final File tempdir = tempdirPath.toFile();
        log.info("Importing " + zip.length + " byte statedump zip file, using temporary directory " + tempdir);

        // Unpack the zip file
        try (final ZipInputStream zipStream = new ZipInputStream(new ByteArrayInputStream(zip))) {
            boolean empty = true;
            long limit = 100_000_000; // Maximum total uncompressed size is 100 MB
            while (true) {
                final ZipEntry entry = zipStream.getNextEntry();
                if (entry == null) { break; }
                if (entry.isDirectory()) {
                    zipStream.closeEntry();
                    continue;
                }

                final String name = entry.getName().replaceFirst("^.*/([^/]+)$", "$1");
                if (name.matches("([a-z0-9_-]+\\.xml|replacements.properties)")) {
                    if (log.isDebugEnabled()) {
                        log.debug("Extracting zip file entry " + name + " into temporary directory");
                    }

                    if (entry.getSize() == 0) {
                        log.debug("Ignoring empty file");
                        zipStream.closeEntry();
                        continue;
                    }

                    // Create file exclusively (don't overwrite, and don't write to special devices or operating system special files)
                    final Path filepath = Files.createFile(new File(tempdir, name).toPath());
                    try (final FileOutputStream fos = new FileOutputStream(filepath.toFile())) {
                        try {
                            limit -= FileTools.streamCopyWithLimit(zipStream, fos, limit);
                        } catch (StreamSizeLimitExceededException ssle) {
                            throw new IOException("Zip file is larger than 100 MB. Aborting.");
                        }
                    }
                    zipStream.closeEntry();
                    empty = false;
                } else if (log.isDebugEnabled()) {
                    log.debug("Ignoring zip file entry " + name);
                }
            }

            if (empty) {
                throw new IOException("Zip file didn't contain any statedump xml files.");
            }

            // Import statedump
            importStatedump(tempdir, lockdown);

        } finally {
            // Clean up
            log.debug("Removing temporary directory for statedump XML files");
            FileUtils.deleteDirectory(tempdir);
        }
    }

    private void lockDownStatedump() throws AuthorizationDeniedException {
        getGlobalConfiguration(); // sets globalConfig
        globalConfig.setStatedumpLockedDown(true);
        getEjbcaWebBean().saveGlobalConfiguration(globalConfig);
        if (log.isDebugEnabled()) {
            final boolean state = getEjbcaWebBean().getGlobalConfiguration().getStatedumpLockedDown();
            log.debug("Statedump lockdown state changed to "+state);
        }
    }

    public void importStatedump() {
        final boolean importFromDir = (statedumpDir != null && !statedumpDir.isEmpty());

        if (!importFromDir && statedumpFile == null) {
            if (statedumpLockdownAfterImport) {
                try {
                    lockDownStatedump();
                } catch (AuthorizationDeniedException e) {
                    final String msg = "Authorization denied: "+e.getLocalizedMessage();
                    log.info(msg);
                    super.addNonTranslatedErrorMessage(msg);
                }
            } else {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Please select a statedump to import.", null));
            }
            return;
        }

        if (importFromDir && statedumpFile != null) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Please import from either a directory or an uploaded ZIP file, but not both.", null));
            return;
        }

        if (getGlobalConfiguration().getStatedumpLockedDown()) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Statedump has been locked down on this EJBCA installation and is not available.", null));
            return;
        }

        try {
            if (importFromDir) {
                final File basedir = new File(statedumpSession.getTemplatesBasedir(getAdmin()));
                importStatedump(new File(basedir, statedumpDir), statedumpLockdownAfterImport);
                super.addNonTranslatedErrorMessage("Statedump imported successfully.");
            } else {
                byte[] uploadedFileBytes = statedumpFile.getBytes();
                importStatedump(uploadedFileBytes, statedumpLockdownAfterImport);
                // This value is only used to cross-check the imported statedump against a key ceremony script, to prevent
                // the wrong statedump from being imported by accident. It has nothing to do with security.
                final String statedumpId = new String(Hex.encodeHex(MessageDigest.getInstance("SHA-256").digest(uploadedFileBytes), false))
                        .substring(0, 6);
                super.addNonTranslatedErrorMessage("Statedump with ID " + statedumpId + " imported successfully.");
            }
        } catch (Exception e) {
            String msg = "Statedump import failed. " + e.getLocalizedMessage();
            log.info(msg, e);
            super.addNonTranslatedErrorMessage(msg);
        }

        // Clear GUI caches
        try {
            getEjbcaWebBean().clearClusterCache(true); // exclude crypto tokens
        } catch (Exception e) {
            String msg = "Statedump was successful, but the cache could not be cleared automatically. Please manually restart your browser or JBoss. " + e.getLocalizedMessage();
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    public boolean validateCurrentConfig() {
        if (!currentConfig.getEnableKeyRecovery()) {
            currentConfig.setLocalKeyRecovery(false);
        }
        if (currentConfig.getLocalKeyRecovery()) {
            if (currentConfig.getLocalKeyRecoveryCryptoTokenId() == 0) {
                String msg = "Please select a crypto token for local key recovery";
                log.info(msg);
                super.addNonTranslatedErrorMessage(msg);
                return false;
            } else if (StringUtils.isEmpty(currentConfig.getLocalKeyRecoveryKeyAlias())) {
                String msg = "Please select a key alias for local key recovery";
                log.info(msg);
                super.addNonTranslatedErrorMessage(msg);
                return false;
            }
        }
        return true;
    }

    private Integer zeroToNull(int value) {
        return value == 0 ? null : value;
    }

    /** Invoked when admin saves the configurations */
    public void saveCurrentConfig() {
        if(currentConfig != null) {
            if (!validateCurrentConfig()) {
                return;
            }
            try {
                globalConfig.setEjbcaTitle(currentConfig.getTitle());
                globalConfig.setHeadBanner(currentConfig.getHeadBanner());
                globalConfig.setFootBanner(currentConfig.getFootBanner());
                globalConfig.setEnableEndEntityProfileLimitations(currentConfig.getEnableEndEntityProfileLimitations());
                globalConfig.setEnableKeyRecovery(currentConfig.getEnableKeyRecovery());
                globalConfig.setLocalKeyRecovery(currentConfig.getLocalKeyRecovery());
                globalConfig.setLocalKeyRecoveryCryptoTokenId(zeroToNull(currentConfig.getLocalKeyRecoveryCryptoTokenId()));
                globalConfig.setLocalKeyRecoveryKeyAlias(currentConfig.getLocalKeyRecoveryKeyAlias());
                globalConfig.setAutoEnrollUse(currentConfig.getUseAutoEnrollment());
                globalConfig.setAutoEnrollCA(currentConfig.getAutoEnrollmentCA());
                globalConfig.setAutoEnrollSSLConnection(currentConfig.getAutoEnrollUseSSLConnection());
                globalConfig.setAutoEnrollADServer(currentConfig.getAutoEnrollAdServer());
                globalConfig.setAutoEnrollADPort(currentConfig.getAutoEnrollAdServerPort());
                globalConfig.setAutoEnrollConnectionDN(currentConfig.getAutoEnrollConnectionDN());
                globalConfig.setAutoEnrollBaseDNUser(currentConfig.getAutoEnrollUserBaseDN());
                globalConfig.setAutoEnrollConnectionPwd(currentConfig.getAutoEnrollConnectionPassword());
                globalConfig.setNodesInCluster(currentConfig.getNodesInCluster());
                globalConfig.setEnableCommandLineInterface(currentConfig.getEnableCommandLine());
                globalConfig.setEnableCommandLineInterfaceDefaultUser(currentConfig.getEnableCommandLineDefaultUser());
                globalConfig.setEnableExternalScripts(currentConfig.getEnableExternalScripts());
                globalConfig.setPublicWebCertChainOrderRootFirst(currentConfig.getPublicWebCertChainOrderRootFirst());
                globalConfig.setUseSessionTimeout(currentConfig.isEnableSessionTimeout());
                globalConfig.setSessionTimeoutTime(currentConfig.getSessionTimeoutTime());
                globalConfig.setEnableIcaoCANameChange(currentConfig.getEnableIcaoCANameChange());

                if (isValidOcspCleanupSettings()) {
                    globalConfig.setOcspCleanupSchedule(currentConfig.getOcspCleanupSchedule());
                    globalConfig.setOcspCleanupScheduleUnit(currentConfig.getOcspCleanupScheduleUnit());
                    globalConfig.setOcspCleanupUse(currentConfig.getOcspCleanupUse());
                }

                LinkedHashMap<Integer, CTLogInfo> ctlogsMap = new LinkedHashMap<>();
                for(CTLogInfo ctlog : currentConfig.getCtLogs()) {
                    ctlogsMap.put(ctlog.getLogId(), ctlog);
                }
                globalConfig.setCTLogs(ctlogsMap);

                if (getGoogleCtPolicy().isValid()) {
                    globalConfig.setGoogleCtPolicy(getGoogleCtPolicy());
                } else {
                    addErrorMessage("INVALID_CT_POLICY");
                }

                getEjbcaWebBean().saveGlobalConfiguration(globalConfig);

                // Restart OCSP cleanup job timers
                ocspCleanupSession.restart();

                globalCesecoreConfiguration.setMaximumQueryCount(currentConfig.getMaximumQueryCount());
                globalCesecoreConfiguration.setMaximumQueryTimeout(currentConfig.getMaximumQueryTimeout());
                getEjbcaWebBean().getEjb().getGlobalConfigurationSession().saveConfiguration(getAdmin(), globalCesecoreConfiguration);
                // Purge access rule for key recovery from all roles if key recovery is disabled
                // This is done after the configuration has been saved successfully, thus making
                // sure the administrator has access to edit the configuration, since no access
                // control check is performed in this step.
                if (!currentConfig.getEnableKeyRecovery()) {
                    log.info("Key recovery has been disabled. Checking if there are any stale access rules to remove...");
                    for (final Role role : roleSession.getAllRoles()) {
                        if (role.getAccessRules().containsKey(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY))) {
                            role.getAccessRules().remove(AccessRulesHelper.normalizeResource(AccessRulesConstants.REGULAR_KEYRECOVERY));
                            roleSession.persistRole(role);
                            log.info("Removed access rule " + AccessRulesConstants.REGULAR_KEYRECOVERY + " from role " + role.getRoleName());
                        }
                    }
                }
            } catch (AuthorizationDeniedException | InvalidConfigurationException e) {
                String msg = "Cannot save System Configuration. " + e.getLocalizedMessage();
                log.info(msg);
                super.addNonTranslatedErrorMessage(msg);
            }

            try {
                adminPreference.setPreferedLanguage(currentConfig.getPreferedLanguage());
                adminPreference.setSecondaryLanguage(currentConfig.getSecondaryLanguage());
                adminPreference.setTheme(currentConfig.getTheme());
                adminPreference.setEntriesPerPage(currentConfig.getEntriesPerPage());

                getEjbcaWebBean().saveDefaultAdminPreference(adminPreference);
            } catch (AuthorizationDeniedException e) {
                String msg = "Cannot save Administrator Preferences. " + e.getLocalizedMessage();
                log.info(msg);
                super.addNonTranslatedErrorMessage(msg);
            }

            // GlobalConfiguration validates and modifies some fields when they are set, so these fields need to be updated.
            // Also, this ensures that the values shown are those actually stored in the database.
            flushCache(); // must be done last
        }
    }

    /** Invoked when admin saves the admin preferences */
    public void saveCurrentAdminPreferences() {
        if(currentConfig != null) {
            try {
                adminPreference.setPreferedLanguage(currentConfig.getPreferedLanguage());
                adminPreference.setSecondaryLanguage(currentConfig.getSecondaryLanguage());
                adminPreference.setTheme(currentConfig.getTheme());
                adminPreference.setEntriesPerPage(currentConfig.getEntriesPerPage());

                getEjbcaWebBean().saveDefaultAdminPreference(adminPreference);
            } catch (Exception e) {
                String msg = "Cannot save Administrator Preferences. " + e.getLocalizedMessage();
                log.info(msg);
                super.addNonTranslatedErrorMessage(msg);
            }
        }
    }

    public void flushCache() {
        globalConfig = null;
        adminPreference = null;
        currentConfig = null;
        nodesInCluster = null;
        ctLogManager = null;
        raStyleInfos = null;
        excludeActiveCryptoTokensFromClearCaches = true;
        availableExtendedKeyUsages = null;
        availableExtendedKeyUsagesConfig = null;
        availableCustomCertExtensions = null;
        availableCustomCertExtensionsConfig = null;
        selectedCustomCertExtensionID = 0;
        googleCtPolicy = null;
        validatorSettings = null;
    }

    public void toggleUseAutoEnrollment() { currentConfig.setUseAutoEnrollment(!currentConfig.getUseAutoEnrollment()); }
    public void toggleEnableKeyRecovery() { currentConfig.setEnableKeyRecovery(!currentConfig.getEnableKeyRecovery()); }
    public void toggleLocalKeyRecovery() { currentConfig.setLocalKeyRecovery(!currentConfig.getLocalKeyRecovery()); }

    public List<SelectItem> getAvailableCryptoTokens() {
        if (availableCryptoTokens == null) {
            availableCryptoTokens = new ArrayList<>();
            for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenManagementSession.getCryptoTokenInfos(getEjbcaWebBean().getAdminObject())) {
                availableCryptoTokens.add(new SelectItem(cryptoTokenInfo.getCryptoTokenId(), cryptoTokenInfo.getName()));
            }
            Collections.sort(availableCryptoTokens, new Comparator<SelectItem>() {
                @Override
                public int compare(final SelectItem o1, final SelectItem o2) {
                    return o1.getLabel().compareToIgnoreCase(o1.getLabel());
                }
            });
            availableCryptoTokens.add(0, new SelectItem(null, getEjbcaWebBean().getText("PLEASE_SELECT_ENCRYPTION_CRYPTOTOKEN")));
        }
        return availableCryptoTokens;
    }

    public void selectLocalKeyRecoveryCryptoToken() {
        availableKeyAliases = null; // force reload
        currentConfig.setLocalKeyRecoveryKeyAlias(null);
        getAvailableKeyAliases();
    }

    public boolean getHasSelectedCryptoToken() {
        return currentConfig.getLocalKeyRecoveryCryptoTokenId() != 0 &&
                cryptoTokenManagementSession.getCryptoTokenInfo(currentConfig.getLocalKeyRecoveryCryptoTokenId()) != null;
    }

    public List<SelectItem> getAvailableKeyAliases() {
        availableKeyAliases = new ArrayList<>();
        if (currentConfig.getLocalKeyRecoveryCryptoTokenId() != 0) {
            try {
                final List<String> aliases = new ArrayList<>(cryptoTokenManagementSession.getKeyPairAliases(getEjbcaWebBean().getAdminObject(), currentConfig.getLocalKeyRecoveryCryptoTokenId()));
                Collections.sort(aliases);
                for (final String keyAlias : aliases) {
                    if (currentConfig.getLocalKeyRecoveryKeyAlias() == null && keyAlias != null &&
                            (keyAlias.startsWith("default") || keyAlias.startsWith("privatedec"))) {
                        currentConfig.setLocalKeyRecoveryKeyAlias(keyAlias);
                    }
                    availableKeyAliases.add(new SelectItem(keyAlias));
                }
                availableKeyAliases.add(0, new SelectItem(null, getEjbcaWebBean().getText("PLEASE_SELECT_KEY")));
            } catch (CryptoTokenOfflineException | AuthorizationDeniedException e) {
                log.debug("Crypto Token is not usable. Can't list key aliases", e);
            }
        }
        return availableKeyAliases;
    }

    /** @return a list of all currently connected nodes in a cluster */
    public ListDataModel<String> getNodesInCluster() {
        if (nodesInCluster == null) {
            List<String> nodesList = getListFromSet(currentConfig.getNodesInCluster());
            nodesInCluster = new ListDataModel<>(nodesList);
        }
        return nodesInCluster;
    }

    /** Invoked when the user wants to a add a new node to the cluster */
    public void addNode() {
        final String nodeToAdd = getCurrentNode();
        Set<String> nodes = currentConfig.getNodesInCluster();
        nodes.add(nodeToAdd);
        currentConfig.setNodesInCluster(nodes);
        nodesInCluster = new ListDataModel<>(getListFromSet(nodes));
    }

    /** Invoked when the user wants to remove a node from the cluster */
    public void removeNode() {
        final String nodeToRemove = nodesInCluster.getRowData();
        Set<String> nodes = currentConfig.getNodesInCluster();
        nodes.remove(nodeToRemove);
        currentConfig.setNodesInCluster(nodes);
        nodesInCluster = new ListDataModel<>(getListFromSet(nodes));
    }

    public boolean isRenderOcspSettings() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    private List<String> getListFromSet(Set<String> set) {
        List<String> list = new ArrayList<>();
        if(set!=null && !set.isEmpty()) {
            for(String entry : set) {
                list.add(entry);
            }
        }
        return list;
    }

    private boolean isValidOcspCleanupSettings() {
        if (currentConfig.getOcspCleanupUse()) {
            final String unit = currentConfig.getOcspCleanupScheduleUnit();
            final Integer interval;

            // Validate number
            try {
                interval = Integer.parseInt(currentConfig.getOcspCleanupSchedule());
            } catch (NumberFormatException ex) {
                addErrorMessage("OCSP_ERROR_NUMBER");
                return false;
            }

            // Validate units and amounts
            if (unit.equals(TimeUnit.DAYS.toString())) {
                if (interval > 31 || interval < 1) {
                    addErrorMessage("OCSP_ERROR_DAYS");
                    return false;
                }
            } else if (unit.equals(TimeUnit.HOURS.toString())) {
                if (interval > 23 || interval < 1) {
                    addErrorMessage("OCSP_ERROR_HOURS");
                    return false;
                }
            } else if (unit.equals(TimeUnit.MINUTES.toString())) {
                if (interval > 59 || interval < 1) {
                    addErrorMessage("OCSP_ERROR_MINUTES");
                    return false;
                }
            } else {
                addErrorMessage("OCSP_ERROR_UNIT");
                return false;
            }
        }

        return true;
    }

    // --------------------------------------------
    //               Protocol Configuration
    // --------------------------------------------

    public AvailableProtocolsConfiguration getAvailableProtocolsConfiguration() {
        return (AvailableProtocolsConfiguration) getEjbcaWebBean().getEjb().getGlobalConfigurationSession()
                    .getCachedConfiguration(AvailableProtocolsConfiguration.CONFIGURATION_ID);
    }

    public void toggleProtocolStatus(final ProtocolGuiInfo protocolToToggle) {
        final AvailableProtocolsConfiguration availableProtocolsConfiguration = getAvailableProtocolsConfiguration();
        if (protocolToToggle.isEnabled()) {
            availableProtocolsConfiguration.setProtocolStatus(protocolToToggle.getProtocol(), false);
        } else {
            availableProtocolsConfiguration.setProtocolStatus(protocolToToggle.getProtocol(), true);
        }
        // Save config
        try {
            getEjbcaWebBean().getEjb().getGlobalConfigurationSession().saveConfiguration(getAdmin(), availableProtocolsConfiguration);
        } catch (AuthorizationDeniedException e) {
            String msg = "Cannot save System Configuration. " + e.getLocalizedMessage();
            log.info("Administrator '" + getAdmin() + "' " + msg);
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    public ArrayList<ProtocolGuiInfo> getAvailableProtocolInfos() {
        ArrayList<ProtocolGuiInfo> protocolInfos = new ArrayList<>();
        LinkedHashMap<String, Boolean> allPC = getAvailableProtocolsConfiguration().getAllProtocolsAndStatus();
        for (Entry<String, Boolean> entry : allPC.entrySet()) {
            protocolInfos.add(new ProtocolGuiInfo(entry.getKey(), entry.getValue()));
        }
        return protocolInfos;
    }

    /** @return true if EST is enabled. Should be false for EJBCA CE */
    public boolean isEstAvailable() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    /** @return true if REST is enabled. Should be false for EJBCA CE */
    public boolean isRestAvailable() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    /** @return true if ACME is enabled. Should be false for EJBCA CE */
    public boolean isAcmeAvailable() {
        return getEjbcaWebBean().isRunningEnterprise();
    }

    public class ProtocolGuiInfo {
        private String protocol;
        private String url;
        private boolean enabled;
        private boolean available;

        public ProtocolGuiInfo(String protocol, boolean enabled) {
            this.protocol = protocol;
            this.enabled = enabled;
            this.url = AvailableProtocols.getContextPathByName(protocol);
            this.available = true;
        }

        /** @return user friendly protocol/service name */
        public String getProtocol() {
            return protocol;
        }

        /** @return URL to service */
        public String getUrl() {
            return url;
        }

        /** @return true if protocol is enabled */
        public boolean isEnabled() {
            return enabled;
        }

        /** @return true if service is available in the deployed instance */
        public boolean isAvailable() {
            if (protocol.equals(AvailableProtocols.EST.getName()) && !isEstAvailable()) {
                available = false;
            }
            if (protocol.equals(AvailableProtocols.REST_CA_MANAGEMENT.getName()) && !isRestAvailable()) {
                available = false;
            }
            if (protocol.equals(AvailableProtocols.REST_CRYPTOTOKEN_MANAGEMENT.getName()) && !isRestAvailable()) {
                available = false;
            }
            if (protocol.equals(AvailableProtocols.REST_CERTIFICATE_MANAGEMENT.getName()) && !isRestAvailable()) {
                available = false;
            }
            if (protocol.equals(AvailableProtocols.ACME.getName()) && !isAcmeAvailable()) {
                available = false;
            }
            return available;
        }

        /** @return user friendly status text. 'Enabled', 'Disabled' or 'Unavailable' if module isn't deployed */
        public String getStatus() {
            if (!isAvailable()) {
                return getEjbcaWebBean().getText("PC_STATUS_UNAVAILABLE");
            }
            return enabled ? getEjbcaWebBean().getText("PC_STATUS_ENABLED") : getEjbcaWebBean().getText("PC_STATUS_DISABLED");
        }
    }



    // --------------------------------------------
    //               Extended Key Usage
    // --------------------------------------------

    private AvailableExtendedKeyUsagesConfiguration availableExtendedKeyUsagesConfig = null;
    private ListDataModel<EKUInfo> availableExtendedKeyUsages = null;
    private String currentEKUOid = "";
    private String currentEKUName = "";

    public String getCurrentEKUOid() { return currentEKUOid; }
    public void setCurrentEKUOid(String oid) { currentEKUOid=oid; }
    public String getCurrentEKUReadableName() { return currentEKUName; }
    public void setCurrentEKUReadableName(String readableName) { currentEKUName=readableName; }

    private void flushNewEKUCache() {
        currentEKUOid = "";
        currentEKUName = "";
    }

    private AvailableExtendedKeyUsagesConfiguration getAvailableEKUConfig() {
        if(availableExtendedKeyUsagesConfig == null) {
            availableExtendedKeyUsagesConfig = getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
        }
        return availableExtendedKeyUsagesConfig;
    }

    public String getEKUOid() {
        return availableExtendedKeyUsages.getRowData().getOid();
    }

    public String getEKUName() {
        return availableExtendedKeyUsages.getRowData().getName();
    }

    public ListDataModel<EKUInfo> getAvailableExtendedKeyUsages() {
        if(availableExtendedKeyUsages == null) {
            availableExtendedKeyUsages = new ListDataModel<>(getNewAvailableExtendedKeyUsages());
        }
        return availableExtendedKeyUsages;
    }

    private ArrayList<EKUInfo> getNewAvailableExtendedKeyUsages() {
        availableExtendedKeyUsagesConfig = getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
        ArrayList<EKUInfo> ekus = new ArrayList<>();
        Map<String, String> allEKU = availableExtendedKeyUsagesConfig.getAllEKUOidsAndNames();
        for (Entry<String, String> entry : allEKU.entrySet()) {
            ekus.add(new EKUInfo(entry.getKey(), getEjbcaWebBean().getText(entry.getValue())));
        }
        Collections.sort(ekus, new Comparator<EKUInfo>() {
            @Override
            public int compare(final EKUInfo ekuInfo1, final EKUInfo ekuInfo2) {
                String[] oidFirst = ekuInfo1.getOid().split("\\.");
                String[] oidSecond = ekuInfo2.getOid().split("\\.");
                int length = Math.min(oidFirst.length, oidSecond.length);
                try {
                    for(int i=0; i<length ; i++) {
                        if(!StringUtils.equals(oidFirst[i], oidSecond[i])) {
                            if(Integer.parseInt(oidFirst[i]) < Integer.parseInt(oidSecond[i])) {
                                return -1;
                            }
                            return 1;
                        }
                    }
                } catch(NumberFormatException e) {
                    log.error("OID contains non-numerical values. This should not happen at this point");
                }

                if(oidFirst.length !=oidSecond.length) {
                    return oidFirst.length < oidSecond.length ? -1 : 1;
                }

                return 0;
            }
        });
        return ekus;
    }

    public void addEKU() {
        AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
        List<String> extKeyUsageNames = ekuConfig.getAllExtKeyUsageName();
        List<String> translatedNames = new ArrayList<String>();
        for (String name : extKeyUsageNames) {
            translatedNames.add(getEjbcaWebBean().getText(name));
        }
        
        if (StringUtils.isEmpty(currentEKUOid)) {
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "No ExtendedKeyUsage OID is set.", null));
            return;
        }
        if (!isOidNumericalOnly(currentEKUOid)) {
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "OID " + currentEKUOid + " contains non-numerical values.", null));
            return;
        }
        if (StringUtils.isEmpty(currentEKUName)) {
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "No ExtendedKeyUsage Name is set.", null));
            return;
        }
        if (ekuConfig.getAllEKUOidsAndNames().containsKey(currentEKUOid)) {
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "OID '" + currentEKUOid + "' already exist.", null));
            return;
        }
        if(translatedNames.contains(currentEKUName)) {
            FacesContext.getCurrentInstance().addMessage(null,
                    new FacesMessage(FacesMessage.SEVERITY_ERROR, "Label '" + currentEKUName + "' already exist.", null));
            return;
        }

        ekuConfig.addExtKeyUsage(currentEKUOid, currentEKUName);
        try {
            getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
            availableExtendedKeyUsages = new ListDataModel<>(getNewAvailableExtendedKeyUsages());
        } catch (Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "Failed to save AvailableExtendedKeyUsagesConfiguration.", e.getLocalizedMessage()));
            return;
        }
        flushNewEKUCache();
    }

    public void removeEKU() {
        final EKUInfo ekuToRemove = (availableExtendedKeyUsages.getRowData());
        final String oid = ekuToRemove.getOid();
        AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
        ekuConfig.removeExtKeyUsage(oid);
        try {
            getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to save AvailableExtendedKeyUsagesConfiguration: " + e.getLocalizedMessage(), null));
            return;
        }
        availableExtendedKeyUsages = new ListDataModel<>(getNewAvailableExtendedKeyUsages());

        ArrayList<String> cpNamesUsingEKU = getCertProfilesUsingEKU(oid);
        if(!cpNamesUsingEKU.isEmpty()) {
            final String cpNamesMessage = getCertProfilesNamesMessage(cpNamesUsingEKU);
            final String message = "ExtendedKeyUsage '" + ekuToRemove.getName() + "' has been removed, but is still used in the following certitifcate profiles: " +  cpNamesMessage;
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_WARN, message, null));
        }
    }

    private ArrayList<String> getCertProfilesUsingEKU(final String oid) {
        ArrayList<String> ret = new ArrayList<>();
        final CertificateProfileSessionLocal certprofileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
        Map<Integer, CertificateProfile> allCertProfiles = certprofileSession.getAllCertificateProfiles();
        for(Entry<Integer, CertificateProfile> entry : allCertProfiles.entrySet()) {
            final CertificateProfile cp = entry.getValue();
            List<String> ekuOids = cp.getExtendedKeyUsageOids();
            if(ekuOids.contains(oid)) {
                ret.add(certprofileSession.getCertificateProfileName(entry.getKey()));
            }
        }
        return ret;
    }

    private String getCertProfilesNamesMessage(final ArrayList<String> certProfileNames) {
        int nrOfProfiles = certProfileNames.size();
        int nrOfdisplayedProfiles = nrOfProfiles>10? 10 : nrOfProfiles;

        StringBuilder sb = new StringBuilder();
        for(int i=0; i<nrOfdisplayedProfiles; i++) {
            sb.append(" " + certProfileNames.get(i) + ",");
        }
        sb.deleteCharAt(sb.length()-1);
        if(nrOfProfiles > nrOfdisplayedProfiles) {
            sb.append(" and " + (nrOfProfiles-nrOfdisplayedProfiles) + " more certificate profiles.");
        }
        return sb.toString();
    }

    private boolean isOidNumericalOnly(String oid) {
        String[] oidParts = oid.split("\\.");
        for(int i=0; i < oidParts.length ; i++) {
            if (oidParts[i].equals("*")) {
                // Allow wildcard characters
                continue;
            }
            try {
                Integer.parseInt(oidParts[i]);
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    // ----------------------------------------------------
    //               Custom RA Styles
    // ----------------------------------------------------

    private GlobalCustomCssConfiguration globalCustomCssConfiguration = null;
    private ListDataModel<RaStyleInfo> raStyleInfos = null;
    private List<RaStyleInfo> raStyleInfosList;
    private UploadedFile raCssFile = null;
    private UploadedFile raLogoFile = null;
    private Map<String, RaCssInfo> importedRaCssInfos = null;
    private String archiveName = null;
    private String logoName = null;
    private byte[] logoBytes = null;

    public GlobalCustomCssConfiguration getGlobalCustomCssConfiguration() {
        if (globalCustomCssConfiguration == null) {
            globalCustomCssConfiguration = (GlobalCustomCssConfiguration) getEjbcaWebBean().getEjb().getGlobalConfigurationSession()
                    .getCachedConfiguration(GlobalCustomCssConfiguration.CSS_CONFIGURATION_ID);
        }
        return globalCustomCssConfiguration;
    }

    public void actionImportRaStyle() {
        // Basic checks
        if (raCssFile == null && raLogoFile == null) {
            addErrorMessage("NOFILESELECTED");
            return;
        }
        if (archiveName == null || archiveName.equals("")) {
            addErrorMessage("STYLENONAME");
            return;
        }
        if (raStyleNameExists(archiveName)) {
            addErrorMessage("STYLEEXISTS", archiveName);
            return;
        }

        try {
            if (!isAllowedToEditSystemConfiguration()) {
                addErrorMessage("CSS_NOT_AUTH");
                log.info("Administrator '" + getAdmin() + "' attempted to import css / logo files. Authorization denied: Insufficient privileges");
                return;
            }
            if (raCssFile != null) {
                // File is selected but something went wrong. Import nothing!
                importCssFromFile();
                if (importedRaCssInfos == null) {
                    return;
                }
            }
            if (raLogoFile != null) {
                importLogoFromImageFile();
                // File is selected but something went wrong. Import nothing!
                if (logoBytes == null) {
                    return;
                }
            }

            RaStyleInfo importedRaStyleInfo = new RaStyleInfo(archiveName, importedRaCssInfos, logoBytes, logoName);
            if (raLogoFile != null) {
                importedRaStyleInfo.setLogoContentType(raLogoFile.getContentType());
            }
            raStyleInfosList.add(importedRaStyleInfo);
            raStyleInfos = new ListDataModel<>(raStyleInfosList);
            saveCustomCssConfiguration();
            importedRaCssInfos = null;
            logoBytes = null;
            logoName = null;

        } catch (IOException | IllegalArgumentException | IllegalStateException e) {
            addErrorMessage("STYLEIMPORTFAIL", e.getLocalizedMessage());
            log.info("Failed to import style files", e);
        }
    }

    private boolean raStyleNameExists(String name) {
        LinkedHashMap<Integer, RaStyleInfo> storedRaStyles = globalCustomCssConfiguration.getRaStyleInfo();
        for (Map.Entry<Integer, RaStyleInfo> raStyle : storedRaStyles.entrySet()) {
            if (raStyle.getValue().getArchiveName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    private void importLogoFromImageFile() throws IOException {
        String contentType = raLogoFile.getContentType();
        if (!contentType.equals("image/jpeg") && !contentType.equals("image/png")) {
            addErrorMessage("LOGOIMPORTIGNORE", raLogoFile.getName());
            return;
        }
        logoName = raLogoFile.getName();
        logoBytes = raLogoFile.getBytes();
        addInfoMessage("LOGOIMPORTSUCCESS", logoName);
    }

    private void importCssFromFile() throws IOException {
        final byte[] fileBuffer = raCssFile.getBytes();
        if (fileBuffer.length == 0) {
            throw new IllegalArgumentException("Empty input file");
        }
        final List<String> importedFiles = new ArrayList<>();
        final List<String> ignoredFiles = new ArrayList<>();
        final Map<String, RaCssInfo> raCssInfosMap = SecureZipUnpacker.Builder.fromByteArray(fileBuffer)
                .onFileIgnored((zipEntry, acceptedFileExtensions) -> ignoredFiles.add(zipEntry.getName()))
                .onFileUnpacked(zipEntry -> importedFiles.add(zipEntry.getName()))
                .onlyUnpackFilesWithFileExtension(".css")
                .build()
                .unpackFilesToMemory()
                .stream()
                .map(unpackedFile -> new RaCssInfo(unpackedFile.getContentAsBytes(), unpackedFile.getFileName()))
                .collect(Collectors.toMap(RaCssInfo::getCssName, Function.identity()));
        if (raCssInfosMap.isEmpty() && raCssFile.getName().endsWith(".css")) {
            // Single file selected (not zip)
            raCssInfosMap.put(raCssFile.getName(), new RaCssInfo(raCssFile.getBytes(), raCssFile.getName()));
            importedFiles.add(raCssFile.getName());
        } else if (raCssInfosMap.isEmpty()) {
            addErrorMessage("CANNOT_PROCESS_ZIP_FILE");
            return;
        }
        if (ignoredFiles.isEmpty()) {
            addInfoMessage("CSSIMPORTSUCCESS", importedFiles.size(), importedFiles);
        } else {
            addInfoMessage("CSSIMPORTIGNORED", importedFiles.size(), importedFiles, ignoredFiles.size(), ignoredFiles);
        }
        importedRaCssInfos = raCssInfosMap;
    }

    public void removeRaStyleInfo() {
        final RaStyleInfo styleToRemove = raStyleInfos.getRowData();
        List<RaStyleInfo> raCssInfosList = getRaStyleInfosList();
        raCssInfosList.remove(styleToRemove);
        setRaStyleInfosList(raCssInfosList);
        raStyleInfos = new ListDataModel<>(raCssInfosList);
        saveCustomCssConfiguration();
    }

    public UploadedFile getRaCssFile() {
        return raCssFile;
    }

    public void setRaCssFile(final UploadedFile raCssFile) {
        this.raCssFile = raCssFile;
    }

    public UploadedFile getRaLogoFile() {
        return raLogoFile;
    }

    public void setRaLogoFile(final UploadedFile raLogoFile) {
        this.raLogoFile = raLogoFile;
    }

    public String getArchiveName() {
        return archiveName;
    }

    public void setArchiveName(String archiveName) {
        this.archiveName = archiveName;
    }

    // Necessary for front end row handling etc.
    public ListDataModel<RaStyleInfo> getRaStyleInfos() {
        if (raStyleInfos == null) {
            List<RaStyleInfo> raCssInfosList = getRaStyleInfosList();
            raStyleInfos = new ListDataModel<>(raCssInfosList);
        }
        return raStyleInfos;
    }

    public List<RaStyleInfo> getRaStyleInfosList() {
        raStyleInfosList = new ArrayList<>(getGlobalCustomCssConfiguration().getRaStyleInfo().values());
        return raStyleInfosList;
    }
    public void setRaStyleInfosList(List<RaStyleInfo> raStyleInfos) {raStyleInfosList = raStyleInfos;}

    private void saveCustomCssConfiguration() {
        LinkedHashMap<Integer, RaStyleInfo> raStyleMap = new LinkedHashMap<>();
        for(RaStyleInfo raStyleInfo : raStyleInfosList) {
            raStyleMap.put(raStyleInfo.getArchiveId(), raStyleInfo);
        }
        globalCustomCssConfiguration.setRaStyle(raStyleMap);
        try {
            getEjbcaWebBean().getEjb().getGlobalConfigurationSession().saveConfiguration(getAdmin(), globalCustomCssConfiguration);
        } catch (AuthorizationDeniedException e) {
            String msg = "Cannot save System Configuration. " + e.getLocalizedMessage();
            log.info("Administrator '" + getAdmin() + "' " + msg);
            super.addNonTranslatedErrorMessage(msg);
        }
    }

    // ----------------------------------------------------
    //               Custom Certificate Extensions
    // ----------------------------------------------------

    private final String DEFAULT_EXTENSION_CLASSPATH = "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension";
    private AvailableCustomCertificateExtensionsConfiguration availableCustomCertExtensionsConfig = null;
    private ListDataModel<CustomCertExtensionInfo> availableCustomCertExtensions = null;
    private int selectedCustomCertExtensionID = 0;
    private String newOID = "";
    private String newDisplayName = "";

    public int getSelectedCustomCertExtensionID() { return selectedCustomCertExtensionID; }
    public void setSelectedCustomCertExtensionID(int id) { selectedCustomCertExtensionID=id; }

    public String getNewOID() { return newOID; }
    public void setNewOID(String oid) { newOID=oid; }
    public String getNewDisplayName() { return newDisplayName; }
    public void setNewDisplayName(String label) { newDisplayName=label; }

    private void flushNewExtensionCache() {
        newOID = "";
        newDisplayName = "";
    }

    private AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsConfig() {
        if(availableCustomCertExtensionsConfig == null) {
            availableCustomCertExtensionsConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        }
        return availableCustomCertExtensionsConfig;
    }

    public ListDataModel<CustomCertExtensionInfo> getAvailableCustomCertExtensions() {
        availableCustomCertExtensions = new ListDataModel<>(getNewAvailableCustomCertExtensions());
        return availableCustomCertExtensions;
    }

    private ArrayList<CustomCertExtensionInfo> getNewAvailableCustomCertExtensions() {
        availableCustomCertExtensionsConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        ArrayList<CustomCertExtensionInfo> extensionsInfo = new ArrayList<>();
        Collection<CertificateExtension> allExtensions = availableCustomCertExtensionsConfig.getAllAvailableCustomCertificateExtensions();
        for(CertificateExtension extension : allExtensions) {
            extensionsInfo.add(new CustomCertExtensionInfo(extension));
        }

        Collections.sort(extensionsInfo, new Comparator<CustomCertExtensionInfo>() {
            @Override
            public int compare(CustomCertExtensionInfo first, CustomCertExtensionInfo second) {
                return Integer.compare(first.getId(), second.getId());
            }
        });

        return extensionsInfo;
    }

    public void removeCustomCertExtension() {
        final CustomCertExtensionInfo extensionToRemove = availableCustomCertExtensions.getRowData();
        final int extID = extensionToRemove.getId();
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableCustomCertExtensionsConfig();
        cceConfig.removeCustomCertExtension(extID);
        try {
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to save AvailableCustomCertificateExtensionsConfiguration: " + e.getLocalizedMessage(), null));
            return;
        }
        availableCustomCertExtensions = new ListDataModel<>(getNewAvailableCustomCertExtensions());

        final ArrayList<String> cpNamedUsingExtension = getCertProfilesUsingExtension(extID);
        if(!cpNamedUsingExtension.isEmpty()) {
            final String cpNamesMessage = getCertProfilesNamesMessage(cpNamedUsingExtension);
            final String message = "CustomCertificateExtension '" + extensionToRemove.getDisplayName() + "' has been removed, but it is still used in the following certitifcate profiles: " +  cpNamesMessage;
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_WARN, message, null));
        }
    }

    public void addCustomCertExtension() {
        String newOID = getNewOID();
        if (StringUtils.isEmpty(newOID)) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExenstion OID is set.", null));
            return;
        }
        if (!isOidNumericalOnly(newOID)) {
            FacesContext.getCurrentInstance()
                    .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "OID " + currentEKUOid + " contains non-numerical values.", null));
            return;
        }

        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableCustomCertExtensionsConfig();

        int newID = generateNewExtensionID(cceConfig);
        if (newID == Integer.MAX_VALUE) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Cannot add more extensions. There are already " + cceConfig.getAllAvailableCustomCertificateExtensions().size() + " extensions.", null));
            return;
        }

        if (StringUtils.isEmpty(getNewDisplayName())) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExension Label is set.", null));
            return;
        }

        try {
            cceConfig.addCustomCertExtension(newID, newOID, getNewDisplayName(), DEFAULT_EXTENSION_CLASSPATH, false, true, new Properties());
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR,
                    "Failed to add Custom Certificate Extension. " + e.getLocalizedMessage() , e.getLocalizedMessage()));
            return;
        }
        availableCustomCertExtensions = new ListDataModel<>(getNewAvailableCustomCertExtensions());
        flushNewExtensionCache();
        flushCache();
    }

    public String actionEdit() {
        selectCurrentRowData();
        customCertificateExtensionViewMode = false;
        return "edit";   // Outcome is defined in faces-config.xml
    }

    public String actionView() {
        selectCurrentRowData();
        customCertificateExtensionViewMode = true;
        return "view";   // Outcome is defined in faces-config.xml
    }

    public boolean getCustomCertificateExtensionViewMode() {
        return customCertificateExtensionViewMode;
    }

    private void selectCurrentRowData() {
        final CustomCertExtensionInfo cceInfo = availableCustomCertExtensions.getRowData();
        selectedCustomCertExtensionID = cceInfo.getId();
    }

    private int generateNewExtensionID(AvailableCustomCertificateExtensionsConfiguration cceConfig) {
        final CertificateProfileSessionLocal certprofileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
        Map<Integer, CertificateProfile> allCertProfiles = certprofileSession.getAllCertificateProfiles();

        int i=0;
        while((cceConfig.isCustomCertExtensionSupported(i) || isExtensionUsedInCertProfiles(i, allCertProfiles)) && (i<Integer.MAX_VALUE)) {
            i++;
        }
        return i;
    }

    private boolean isExtensionUsedInCertProfiles(final int id, final Map<Integer, CertificateProfile> allCertProfiles) {
        for(Entry<Integer, CertificateProfile> entry : allCertProfiles.entrySet()) {
            final CertificateProfile cp = entry.getValue();
            List<Integer> usedCertExts = cp.getUsedCertificateExtensions();
            if(usedCertExts.contains(id)) {
                return true;
            }
        }
        return false;
    }

    private ArrayList<String> getCertProfilesUsingExtension(final int id) {
        ArrayList<String> ret = new ArrayList<>();
        final CertificateProfileSessionLocal certprofileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
        Map<Integer, CertificateProfile> allCertProfiles = certprofileSession.getAllCertificateProfiles();
        for(Entry<Integer, CertificateProfile> entry : allCertProfiles.entrySet()) {
            final CertificateProfile cp = entry.getValue();
            List<Integer> usedCertExts = cp.getUsedCertificateExtensions();
            if(usedCertExts.contains(id)) {
                ret.add(certprofileSession.getCertificateProfileName(entry.getKey()));
            }
        }
        return ret;
    }

    /** @return true if admin may create new or modify System Configuration. */
    public boolean isAllowedToEditSystemConfiguration() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }

    /** @return true if admin may create new or modify existing Extended Key Usages. */
    public boolean isAllowedToEditExtendedKeyUsages() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_EDIT.resource());
    }

    /** @return true if admin may create new or modify existing Custom Certificate Extensions. */
    public boolean isAllowedToEditCustomCertificateExtension() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource());
    }

    // ------------------------------------------------
    //             Drop-down menu options
    // ------------------------------------------------
    /** @return a list of all CA names */
    public List<SelectItem> getAvailableCAsAndNoEncryptionOption() {
        final List<SelectItem> ret = getAvailableCAs();
        ret.add(new SelectItem(0, "No encryption"));
        return ret;
    }

    /** @return a list of all CA names and caids */
    public List<SelectItem> getAvailableCAs() {
        final List<SelectItem> ret = new ArrayList<>();
        Map<Integer, String> caidToName = caSession.getCAIdToNameMap();
        List<Integer> allCaIds = caSession.getAllCaIds();
        for(int caid : allCaIds) {
            if (caSession.authorizedToCANoLogging(getAdmin(), caid)) {
                String caname = caidToName.get(caid);
                ret.add(new SelectItem(caid, caname));
            } else {
                ret.add(new SelectItem(0, "<Unauthorized CA>", "A CA that the current admin lack access to.", true));
            }
        }
        return ret;
    }

    public List<SelectItem> getAvailableOcspCleanupUnits() {
        final List<SelectItem> units = new ArrayList<>();
        final String days = TimeUnit.DAYS.toString();
        final String hours = TimeUnit.HOURS.toString();
        final String minutes = TimeUnit.MINUTES.toString();

        // Minutes
        units.add(new SelectItem(minutes, StringUtils.capitalize(minutes.toLowerCase())));

        // Hours
        units.add(new SelectItem(hours, StringUtils.capitalize(hours.toLowerCase())));

        // Days
        units.add(new SelectItem(days, StringUtils.capitalize(days.toLowerCase())));

        return units;
    }

    public List<SelectItem> getAvailableLanguageSelectItems() {
        final List<SelectItem> selectItems = new ArrayList<>();
        final List<WebLanguage> availableWebLanguages = getEjbcaWebBean().getWebLanguagesList();
        for (final WebLanguage availableWebLanguage : availableWebLanguages) {
            final SelectItem languageSelectItem = new SelectItem(availableWebLanguage.getId(), availableWebLanguage.toString());
            selectItems.add(languageSelectItem);
        }
        return selectItems;
    }

    public List<SelectItem> getAvailableThemes() {
        final List<SelectItem> ret = new ArrayList<>();
        final String[] themes = getGlobalConfiguration().getAvailableThemes();
        for(String theme : themes) {
            ret.add(new SelectItem(theme, theme));
        }
        return ret;
    }

    public List<SelectItem> getPossibleEntriesPerPage() {
        final List<SelectItem> ret = new ArrayList<>();
        final String[] possibleValues = getGlobalConfiguration().getPossibleEntiresPerPage();
        for(String value : possibleValues) {
            ret.add(new SelectItem(Integer.parseInt(value), value));
        }
        return ret;
    }

    public List<String> getAvailableTabs() {
        final List<String> availableTabs = new ArrayList<>();
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Basic Configurations");
            availableTabs.add("Administrator Preferences");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Protocol Configuration");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Extended Key Usages");
        }
        if (getEjbcaWebBean().isRunningBuildWithCA()
                && authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())
                && CertificateTransparencyFactory.isCTAvailable()) {
            availableTabs.add("Certificate Transparency Logs");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Custom Certificate Extensions");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.ROLE_ROOT.resource())) {
            availableTabs.add("Custom RA Styles");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.ROLE_ROOT.resource()) && isStatedumpAvailable()) {
            availableTabs.add("Statedump");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            availableTabs.add("External Scripts");
        }
        if (authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Configuration Checker");
        }
        return availableTabs;
    }

}
