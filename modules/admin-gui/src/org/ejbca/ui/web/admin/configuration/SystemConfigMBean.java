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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.config.InvalidConfigurationException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.StreamSizeLimitExceededException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.statedump.ejb.StatedumpImportOptions;
import org.ejbca.statedump.ejb.StatedumpImportResult;
import org.ejbca.statedump.ejb.StatedumpObjectKey;
import org.ejbca.statedump.ejb.StatedumpResolution;
import org.ejbca.statedump.ejb.StatedumpSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * 
 * Backing bean for the various system configuration pages. 
 * 
 * @version $Id$
 *
 */

public class SystemConfigMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -6653610614851741905L;
    private static final Logger log = Logger.getLogger(SystemConfigMBean.class);

    /** GUI table representation of a SCEP alias that can be interacted with. */
    public class GuiInfo {
        private String title;
        private String headBanner;
        private String footBanner;
        private boolean enableEndEntityProfileLimitations;
        private boolean enableKeyRecovery;
        private boolean enableIcaoCANameChange;
        private boolean issueHardwareToken;
        private int hardTokenDataEncryptCA;
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
        private List<CTLogInfo> ctLogs;
        private boolean publicWebCertChainOrderRootFirst;
        
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
                this.issueHardwareToken = globalConfig.getIssueHardwareTokens();
                this.hardTokenDataEncryptCA = globalConfig.getHardTokenEncryptCA();
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
                this.publicWebCertChainOrderRootFirst = globalConfig.getPublicWebCertChainOrderRootFirst();
                this.setEnableIcaoCANameChange(globalConfig.getEnableIcaoCANameChange());
                
                ArrayList<CTLogInfo> ctlogs = new ArrayList<CTLogInfo>();
                Map<Integer, CTLogInfo> availableCTLogs = globalConfig.getCTLogs();
                for(int logid : availableCTLogs.keySet()) {
                    ctlogs.add(availableCTLogs.get(logid));
                }
                this.ctLogs = ctlogs;
                
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
            } catch (CADoesntExistsException e) {
                log.error(e.getLocalizedMessage(), e);
            } catch (Exception e) {
                log.error(e.getLocalizedMessage(), e);
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
        public boolean getIssueHardwareToken() { return this.issueHardwareToken; }
        public void setIssueHardwareToken(boolean issueHWtoken) { this.issueHardwareToken=issueHWtoken; }
        public int getHardTokenDataEncryptCA() { return hardTokenDataEncryptCA; }
        public void setHardTokenDataEncryptCA(int caid) { this.hardTokenDataEncryptCA=caid; }
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
        public List<CTLogInfo> getCtLogs() {return this.ctLogs; }
        public void setCtLogs(List<CTLogInfo> ctlogs) { this.ctLogs=ctlogs; }
        public boolean getPublicWebCertChainOrderRootFirst() { return this.publicWebCertChainOrderRootFirst; }
        public void setPublicWebCertChainOrderRootFirst(boolean publicWebCertChainOrderRootFirst) { this.publicWebCertChainOrderRootFirst=publicWebCertChainOrderRootFirst; }
        public boolean getEnableIcaoCANameChange() {return enableIcaoCANameChange;}
        public void setEnableIcaoCANameChange(boolean enableIcaoCANameChange) {this.enableIcaoCANameChange = enableIcaoCANameChange;}
        
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
        private String encoding;
        
        public CustomCertExtensionInfo(CertificateExtension extension) {
            this.id = extension.getId();
            this.oid = extension.getOID();
            this.displayName = getEjbcaWebBean().getText(extension.getDisplayName());
            this.critical = extension.isCriticalFlag();
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
        public String getEncoding() { return this.encoding; }
    }
    
    private String selectedTab = null;
    private GlobalConfiguration globalConfig = null;
    private GlobalCesecoreConfiguration globalCesecoreConfiguration = null;
    private AdminPreference adminPreference = null;
    private GuiInfo currentConfig = null;
    private ListDataModel<String> nodesInCluster = null;
    private String currentNode = null;
    private ListDataModel<CTLogInfo> ctLogs = null;
    private String currentCTLogURL = null;
    private int currentCTLogTimeout;
    private UploadedFile currentCTLogPublicKeyFile = null;
    private boolean excludeActiveCryptoTokensFromClearCaches = true;
    private boolean customCertificateExtensionViewMode = false;
    private UploadedFile statedumpFile = null;
    private String statedumpDir = null;
    private boolean statedumpLockdownAfterImport = false;
    
    private final CaSessionLocal caSession = getEjbcaWebBean().getEjb().getCaSession();
    private final CertificateProfileSessionLocal certificateProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final AccessControlSessionLocal accessControlSession = getEjbcaWebBean().getEjb().getAccessControlSession();
    /** Session bean for importing statedump. Will be null if statedump isn't available */
    private final StatedumpSessionLocal statedumpSession = new EjbLocalHelper().getStatedumpSession();

    
    public SystemConfigMBean() {
        super();
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
    
    public String getCurrentCTLogURL() {
        return currentCTLogURL;
    }
    
    public void setCurrentCTLogURL(String url) {
        this.currentCTLogURL = url;
    }
    
    public int getCurrentCTLogTimeout() {
        return this.currentCTLogTimeout;
    }
    
    public void setCurrentCTLogTimeout(int timeout) {
        this.currentCTLogTimeout = timeout;
    }
    
    public UploadedFile getCurrentCTLogPublicKeyFile() {
        return this.currentCTLogPublicKeyFile;
    }

    public void setCurrentCTLogPublicKeyFile(UploadedFile publicKeyFile) {
        this.currentCTLogPublicKeyFile = publicKeyFile;
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
        log.info("Statedump successfully imported.");
        
        // Lock down after import
        if (lockdown) {
            log.info("Locking down Statedump in the Admin Web.");
            lockDownStatedump();
        } else {
            log.debug("Not locking down statedump.");
        }
        
        // Done, add result messages
        for (String msg : result.getNotices()) {
            super.addNonTranslatedInfoMessage(msg);
        }
        super.addNonTranslatedInfoMessage("State dump was successfully imported.");
    }
    
    private void importStatedump(byte[] zip, boolean lockdown) throws IOException, AuthorizationDeniedException {
        // Check that it's a ZIP file
        if (zip.length < 2 || zip[0] != 'P' || zip[1] != 'K') {
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
            } else {
                byte[] uploadedFileBytes = statedumpFile.getBytes();
                importStatedump(uploadedFileBytes, statedumpLockdownAfterImport);
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
            String msg = "Statedump was successfull, but the cached could not be cleared automatically. Please manually restart your browser or JBoss. "+ e.getLocalizedMessage();
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
    }
    
    /** Invoked when admin saves the configurations */
    public void saveCurrentConfig() {
        if(currentConfig != null) {
            try {
                globalConfig.setEjbcaTitle(currentConfig.getTitle());
                globalConfig.setHeadBanner(currentConfig.getHeadBanner());
                globalConfig.setFootBanner(currentConfig.getFootBanner());
                globalConfig.setEnableEndEntityProfileLimitations(currentConfig.getEnableEndEntityProfileLimitations());
                globalConfig.setEnableKeyRecovery(currentConfig.getEnableKeyRecovery());
                globalConfig.setIssueHardwareTokens(currentConfig.getIssueHardwareToken());
                globalConfig.setHardTokenEncryptCA(currentConfig.getHardTokenDataEncryptCA());
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
                globalConfig.setPublicWebCertChainOrderRootFirst(currentConfig.getPublicWebCertChainOrderRootFirst());
                globalConfig.setEnableIcaoCANameChange(currentConfig.getEnableIcaoCANameChange());
                Map<Integer, CTLogInfo> ctlogsMap = new HashMap<Integer, CTLogInfo>();
                for(CTLogInfo ctlog : currentConfig.getCtLogs()) {
                    ctlogsMap.put(ctlog.getLogId(), ctlog);
                }
                globalConfig.setCTLogs(ctlogsMap);

                getEjbcaWebBean().saveGlobalConfiguration(globalConfig);
                
                globalCesecoreConfiguration.setMaximumQueryCount(currentConfig.getMaximumQueryCount());
                globalCesecoreConfiguration.setMaximumQueryTimeout(currentConfig.getMaximumQueryTimeout());
                getEjbcaWebBean().getEjb().getGlobalConfigurationSession().saveConfiguration(getAdmin(), globalCesecoreConfiguration);
             
                
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
        ctLogs = null;
        excludeActiveCryptoTokensFromClearCaches = true;
        availableExtendedKeyUsages = null;
        availableExtendedKeyUsagesConfig = null;
        availableCustomCertExtensions = null;
        availableCustomCertExtensionsConfig = null;
        selectedCustomCertExtensionID = 0;
    }
    
    public void toggleUseAutoEnrollment() {
        currentConfig.setUseAutoEnrollment(!currentConfig.getUseAutoEnrollment());
    }
    
    /** @return a list of all currently connected nodes in a cluster */
    public ListDataModel<String> getNodesInCluster() {
        if (nodesInCluster == null) {
            List<String> nodesList = getListFromSet(currentConfig.getNodesInCluster());
            nodesInCluster = new ListDataModel<String>(nodesList);
        }
        return nodesInCluster;
    }

    /** Invoked when the user wants to a add a new node to the cluster */
    public void addNode() {
        final String nodeToAdd = getCurrentNode();
        Set<String> nodes = currentConfig.getNodesInCluster(); 
        nodes.add(nodeToAdd);
        currentConfig.setNodesInCluster(nodes);
        nodesInCluster = new ListDataModel<String>(getListFromSet(nodes));
    }

    /** Invoked when the user wants to remove a node from the cluster */
    public void removeNode() {
        final String nodeToRemove = (String) nodesInCluster.getRowData();
        Set<String> nodes = currentConfig.getNodesInCluster(); 
        nodes.remove(nodeToRemove);
        currentConfig.setNodesInCluster(nodes);
        nodesInCluster = new ListDataModel<String>(getListFromSet(nodes));
    }
    
    private List<String> getListFromSet(Set<String> set) {
        List<String> list = new ArrayList<String>();
        if(set!=null && !set.isEmpty()) {
            for(String entry : set) {
                list.add(entry);
            }
        }
        return list;
    }
    
    
    // -------------------------------------------
    //                 CTLogs
    // -------------------------------------------
    
    public String getCtLogUrl() {
        return ctLogs.getRowData().getUrl();
    }
    
    public int getCtLogTimeout() {
        return ctLogs.getRowData().getTimeout();
    }
    
    public String getCtLogPublicKeyID() {
        return ctLogs.getRowData().getLogKeyIdString();
    }
    
    public ListDataModel<CTLogInfo> getCtLogs() {
        if (ctLogs == null) {
            List<CTLogInfo> logs = getCurrentConfig().getCtLogs();
            ctLogs = new ListDataModel<>(logs);
        }
        return ctLogs;
    }
    
    public void addCTLog() {
        
        if (currentCTLogURL == null || !currentCTLogURL.contains("://")) {
            addErrorMessage("CTLOGTAB_MISSINGPROTOCOL");
            return;
        }
        if (currentCTLogPublicKeyFile == null) {
            addErrorMessage("CTLOGTAB_UPLOADFAILED");
            return;
        }
        final int timeout = getCurrentCTLogTimeout();
        if (timeout < 0) {
            addErrorMessage("CTLOGTAB_TIMEOUTNEGATIVE");
            return;
        }
        
        final CTLogInfo ctlogToAdd;
        try {
            byte[] uploadedFileBytes = currentCTLogPublicKeyFile.getBytes();
            byte[] keybytes = KeyTools.getBytesFromPublicKeyFile(uploadedFileBytes);
            ctlogToAdd = new CTLogInfo(CTLogInfo.fixUrl(currentCTLogURL), keybytes);
            ctlogToAdd.setTimeout(timeout);
        } catch (IOException e) {
            log.info("Could not parse the public key file", e);
            addErrorMessage("CTLOGTAB_BADKEYFILE", getCurrentCTLogPublicKeyFile().getName(), e.getLocalizedMessage());
            return;
        } catch (Exception e) {
            log.info("Failed to add CT Log", e);
            addErrorMessage("CTLOGTAB_GENERICADDERROR", e.getLocalizedMessage());
            return;
        }

        for (CTLogInfo existing : currentConfig.getCtLogs()) {
            if (StringUtils.equals(existing.getUrl(), ctlogToAdd.getUrl())) {
                addErrorMessage("CTLOGTAB_ALREADYEXISTS", existing.getUrl());
                return;
            }
        }
        
        List<CTLogInfo> ctlogs = currentConfig.getCtLogs(); 
        ctlogs.add(ctlogToAdd);
        currentConfig.setCtLogs(ctlogs);
        ctLogs = new ListDataModel<>(ctlogs);
        
        saveCurrentConfig();
    }

    public void removeCTLog() {
        final CTLogInfo ctlogToRemove = ctLogs.getRowData();
        
        // Check if it's in use by certificate profiles
        final List<String> usedByProfiles = new ArrayList<>();
        final Map<Integer,String> idToName = certificateProfileSession.getCertificateProfileIdToNameMap();
        for (Entry<Integer,CertificateProfile> entry : certificateProfileSession.getAllCertificateProfiles().entrySet()) {
            final int certProfId = entry.getKey();
            final CertificateProfile certProf = entry.getValue();
            if (certProf.getEnabledCTLogs().contains(ctlogToRemove.getLogId())) {
                usedByProfiles.add(idToName.get(certProfId));
            }
        }
        
        if (!usedByProfiles.isEmpty()) {
            addErrorMessage("CTLOGTAB_INUSEBYPROFILES", StringUtils.join(usedByProfiles, ", "));
            return;
        }
        
        List<CTLogInfo> ctlogs = currentConfig.getCtLogs(); 
        ctlogs.remove(ctlogToRemove);
        currentConfig.setCtLogs(ctlogs);
        ctLogs = new ListDataModel<>(ctlogs);
        saveCurrentConfig();
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
        return ((EKUInfo) availableExtendedKeyUsages.getRowData()).getOid();
    }
    
    public String getEKUName() {
        return ((EKUInfo) availableExtendedKeyUsages.getRowData()).getName();
    }
    
    public ListDataModel<EKUInfo> getAvailableExtendedKeyUsages() {
        if(availableExtendedKeyUsages == null) {
            availableExtendedKeyUsages = new ListDataModel<EKUInfo>(getNewAvailableExtendedKeyUsages());
        }
        return availableExtendedKeyUsages;
    }
    
    private ArrayList<EKUInfo> getNewAvailableExtendedKeyUsages() {
        availableExtendedKeyUsagesConfig = getEjbcaWebBean().getAvailableExtendedKeyUsagesConfiguration();
        ArrayList<EKUInfo> ekus = new ArrayList<EKUInfo>();
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
        
        if (StringUtils.isEmpty(currentEKUOid)) {
            FacesContext.getCurrentInstance()
                    .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No ExtendedKeyUsage OID is set.", null));
            return;
        }
        if (!isOidNumericalOnly(currentEKUOid)) {
            FacesContext.getCurrentInstance()
                    .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "OID " + currentEKUOid + " contains non-numerical values.", null));
            return;
        }
        if (StringUtils.isEmpty(currentEKUName)) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No ExtendedKeyUsage Name is set.", null));
            return;
        }
        
        AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
        ekuConfig.addExtKeyUsage(currentEKUOid, currentEKUName);
        try {
            getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
            availableExtendedKeyUsages = new  ListDataModel<EKUInfo>(getNewAvailableExtendedKeyUsages());
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to save AvailableExtendedKeyUsagesConfiguration.", e.getLocalizedMessage()));
            return;
        }
        flushNewEKUCache();
    }

    public void removeEKU() {
        final EKUInfo ekuToRemove = ((EKUInfo) availableExtendedKeyUsages.getRowData());
        final String oid = ekuToRemove.getOid();
        AvailableExtendedKeyUsagesConfiguration ekuConfig = getAvailableEKUConfig();
        ekuConfig.removeExtKeyUsage(oid);
        try {
            getEjbcaWebBean().saveAvailableExtendedKeyUsagesConfiguration(ekuConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to save AvailableExtendedKeyUsagesConfiguration: " + e.getLocalizedMessage(), null));
            return;
        }
        availableExtendedKeyUsages = new ListDataModel<EKUInfo>(getNewAvailableExtendedKeyUsages());
        
        ArrayList<String> cpNamesUsingEKU = getCertProfilesUsingEKU(oid);
        if(!cpNamesUsingEKU.isEmpty()) {
            final String cpNamesMessage = getCertProfilesNamesMessage(cpNamesUsingEKU);
            final String message = "ExtendedKeyUsage '" + ekuToRemove.getName() + "' has been removed, but is still used in the following certitifcate profiles: " +  cpNamesMessage;
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_WARN, message, null));            
        }
    }
    
    private ArrayList<String> getCertProfilesUsingEKU(final String oid) {
        ArrayList<String> ret = new ArrayList<String>();
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
        for(int i=0; i<oidParts.length ; i++) {
            try {
                Integer.parseInt(oidParts[i]);
            } catch(NumberFormatException e) {
                return false;
            }
        }
        return true;
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
        availableCustomCertExtensions = new ListDataModel<CustomCertExtensionInfo>(getNewAvailableCustomCertExtensions());
        return availableCustomCertExtensions;
    }
    
    private ArrayList<CustomCertExtensionInfo> getNewAvailableCustomCertExtensions() {
        availableCustomCertExtensionsConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        ArrayList<CustomCertExtensionInfo> extensionsInfo = new ArrayList<CustomCertExtensionInfo>();
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
        final CustomCertExtensionInfo extensionToRemove = (CustomCertExtensionInfo) availableCustomCertExtensions.getRowData();
        final int extID = extensionToRemove.getId();
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableCustomCertExtensionsConfig();
        cceConfig.removeCustomCertExtension(extID);
        try {
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to save AvailableCustomCertificateExtensionsConfiguration: " + e.getLocalizedMessage(), null));
            return;
        }
        availableCustomCertExtensions = new ListDataModel<CustomCertExtensionInfo>(getNewAvailableCustomCertExtensions());
        
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
            cceConfig.addCustomCertExtension(newID, newOID, getNewDisplayName(), DEFAULT_EXTENSION_CLASSPATH, false, new Properties());
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, 
                    "Failed to add Custom Certificate Extension. " + e.getLocalizedMessage() , e.getLocalizedMessage()));
            return;
        }
        availableCustomCertExtensions = new ListDataModel<CustomCertExtensionInfo>(getNewAvailableCustomCertExtensions());
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
        final CustomCertExtensionInfo cceInfo = (CustomCertExtensionInfo) availableCustomCertExtensions.getRowData();
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
        ArrayList<String> ret = new ArrayList<String>();
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
        return accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_EDIT.resource());
    }
    
    /** @return true if admin may create new or modify existing Extended Key Usages. */
    public boolean isAllowedToEditExtendedKeyUsages() {
        return accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_EDIT.resource());
    }
    
    /** @return true if admin may create new or modify existing Custom Certificate Extensions. */
    public boolean isAllowedToEditCustomCertificateExtension() {
        return accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource());
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
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        Map<Integer, String> caidToName = getEjbcaWebBean().getInformationMemory().getCAIdToNameMap();
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
    
    public List<SelectItem> getAvailableLanguages() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final String[] availableLanguages = getEjbcaWebBean().getAvailableLanguages();
        final String[] availableLanguagesEnglishNames = getEjbcaWebBean().getLanguagesEnglishNames();
        final String[] availableLanguagesNativeNames = getEjbcaWebBean().getLanguagesNativeNames();
        for(int i=0; i<availableLanguages.length; i++) {
            String output = availableLanguagesEnglishNames[i];
            if((availableLanguagesEnglishNames != null) && (availableLanguagesNativeNames[i] != null)) {
                output += " - ";
            }
            output += availableLanguagesNativeNames[i];
            if((availableLanguagesEnglishNames != null) || (availableLanguagesNativeNames[i] != null)) {
                output += " ";
            }
            output += "[" + availableLanguages[i] + "]";
            ret.add(new SelectItem(i, output));
        }
        return ret;
    }
    
    public List<SelectItem> getAvailableThemes() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final String[] themes = globalConfig.getAvailableThemes();
        for(String theme : themes) {
            ret.add(new SelectItem(theme, theme));
        }
        return ret;
    }
    
    public List<SelectItem> getPossibleEntriesPerPage() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        final String[] possibleValues = globalConfig.getPossibleEntiresPerPage();
        for(String value : possibleValues) {
            ret.add(new SelectItem(Integer.parseInt(value), value));
        }
        return ret;
    }
    
    public List<String> getAvailableTabs() {
        AccessControlSession accessControlSession = getEjbcaWebBean().getEjb().getAccessControlSession();
        final List<String> availableTabs = new ArrayList<String>();
        if (accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Basic Configurations");
            availableTabs.add("Administrator Preferences");
        }
        if (accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.EKUCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Extended Key Usages");
        }
        if (accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.SYSTEMCONFIGURATION_VIEW.resource()) && CertificateTransparencyFactory.isCTAvailable()) {
            availableTabs.add("Certificate Transparency Logs");
        }
        if (accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_VIEW.resource())) {
            availableTabs.add("Custom Certificate Extensions");
        }
        if (accessControlSession.isAuthorizedNoLogging(getAdmin(), true, StandardRules.ROLE_ROOT.resource()) && isStatedumpAvailable()) {
            availableTabs.add("Statedump");
        }
        return availableTabs;
    }
    
}
