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

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.util.StringTools;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.msae.ADConnectionSingletonLocal;
import org.ejbca.core.protocol.msae.LDAPException;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for MSAutoEnrollmentConfiguration in System Settings.
 */
@Named("msAutoEnrollmentSettings")
@ViewScoped
public class MSAutoEnrollmentSettingsManagedBean extends BaseManagedBean {
    
    @Inject
    private AutoenrollmentConfigMBean autoenrollmentConfigMBean;
    
    private static final Logger log = Logger.getLogger(MSAutoEnrollmentSettingsManagedBean.class);
    private static final long serialVersionUID = 1L;

    private static final String HIDDEN_PWD = "**********";

    private static final String SELECT_CEP = "Select a Certificate Profile";
    private static final String SELECT_EEP = "Select an End Entity Profile";
    private static final String SELECT_MST = "Select a Template";
    private static final String KEYTAB_CONTENT_TYPE = "application/octet-stream";
    private static final String KRB5_CONF_CONTENT_TYPE = "application/octet-stream";

    
    // MSAE Kerberos Settings
    private String msaeForestRoot;
    private String msaeDomain;
    private UploadedFile keyTabFile;
    private String keyTabFilename;
    private byte[] keyTabFileBytes;
    
    // MSAE Krb5Conf Settings
    private UploadedFile krb5ConfFile;
    private String krb5ConfFilename;
    private byte[] krb5ConfFileBytes;    

    private String policyName;
    private String servicePrincipalName;

    // MSAE Settings
    private boolean isUseSSL;
    private boolean followLdapReferral;
    private int adConnectionPort;
    private int ldapReadTimeout;
    private int ldapConnectTimeout;
    private String adLoginDN;
    private String adLoginPassword;
    private Integer authKeyBinding;

    // MS Servlet Settings
    private String caName;

    // MS Template Settings: Holds mapped MS Templates for the configuration
    private List<MSAutoEnrollmentSettingsTemplate> mappedMsTemplates;
    private ListDataModel<MSAutoEnrollmentSettingsTemplate> mappedMsTemplatesModel;
    private List<MSAutoEnrollmentSettingsTemplate> availableTemplates;

    private String selectedTemplateOid;
    private String selectedCertificateProfileName;
    private Integer selectedCertificateProfileId;
    private String selectedEndEntityProfileName;
    private Integer selectedEndEntityProfileId;
    private IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
    private IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();

    @EJB
    private ADConnectionSingletonLocal adConnection;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    
    @PostConstruct
    public void loadConfiguration() {

        final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

        this.authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        this.authorizedCertificateProfiles = raMasterApiProxyBean.getAuthorizedCertificateProfiles(getAdmin());
        
        if (autoEnrollmentConfiguration != null) {
            msaeForestRoot = autoEnrollmentConfiguration.getMsaeForestRoot(autoenrollmentConfigMBean.getSelectedAlias());
            msaeDomain = autoEnrollmentConfiguration.getMsaeDomain(autoenrollmentConfigMBean.getSelectedAlias());
            policyName = autoEnrollmentConfiguration.getPolicyName(autoenrollmentConfigMBean.getSelectedAlias());
            servicePrincipalName = autoEnrollmentConfiguration.getSpn(autoenrollmentConfigMBean.getSelectedAlias());
            keyTabFileBytes = autoEnrollmentConfiguration.getMsaeKeyTabBytes(autoenrollmentConfigMBean.getSelectedAlias());
            keyTabFilename = autoEnrollmentConfiguration.getMsaeKeyTabFilename(autoenrollmentConfigMBean.getSelectedAlias());
            
            krb5ConfFileBytes = autoEnrollmentConfiguration.getMsaeKrb5ConfBytes(autoenrollmentConfigMBean.getSelectedAlias());
            krb5ConfFilename = autoEnrollmentConfiguration.getMsaeKrb5ConfFilename(autoenrollmentConfigMBean.getSelectedAlias());

            isUseSSL = autoEnrollmentConfiguration.isUseSSL(autoenrollmentConfigMBean.getSelectedAlias());
            followLdapReferral = autoEnrollmentConfiguration.isFollowLdapReferral(autoenrollmentConfigMBean.getSelectedAlias());
            adConnectionPort = autoEnrollmentConfiguration.getADConnectionPort(autoenrollmentConfigMBean.getSelectedAlias());
            ldapReadTimeout = autoEnrollmentConfiguration.getLdapReadTimeout(autoenrollmentConfigMBean.getSelectedAlias());
            ldapConnectTimeout = autoEnrollmentConfiguration.getLdapConnectTimeout(autoenrollmentConfigMBean.getSelectedAlias());

            adLoginDN = autoEnrollmentConfiguration.getAdLoginDN(autoenrollmentConfigMBean.getSelectedAlias());
            adLoginPassword = MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD;
            authKeyBinding = autoEnrollmentConfiguration.getAuthKeyBinding(autoenrollmentConfigMBean.getSelectedAlias());

            caName = autoEnrollmentConfiguration.getCaName(autoenrollmentConfigMBean.getSelectedAlias());

            mappedMsTemplates = autoEnrollmentConfiguration.getMsTemplateSettings(autoenrollmentConfigMBean.getSelectedAlias());
        }
    }

    // MSAE Kerberos Settings
    
    public String getMsaeForestRoot() {
        return msaeForestRoot;
    }
    
    public void setMsaeForestRoot(String msaeForestRoot) {
        this.msaeForestRoot = msaeForestRoot;
    }
    
    public String getMsaeDomain() {
        return msaeDomain;
    }

    public void setMsaeDomain(String msaeDomain) {
        this.msaeDomain = msaeDomain;
    }

    public String getPolicyName() {
        return policyName;
    }

    public void setPolicyName(String policyName) {
        this.policyName = policyName;
    }
    
    public String getServicePrincipalName() {
        return servicePrincipalName;
    }

    public void setServicePrincipalName(String servicePrincipalName) {
        this.servicePrincipalName = servicePrincipalName;
    }

    public UploadedFile getKeyTabFile() {
        return keyTabFile;
    }

    public void setKeyTabFile(UploadedFile keyTabFile) {
        this.keyTabFile = keyTabFile;
    }

    public String getKeyTabFilename() {
        return keyTabFilename;
    }

    public void setKeyTabFilename(String keyTabFilename) {
        this.keyTabFilename = StringTools.stripFilename(keyTabFilename);
    }

    public byte[] getKeyTabFileBytes() {
        return keyTabFileBytes;
    }

    public void setKeyTabFileBytes(byte[] keyTabFileBytes) {
        this.keyTabFileBytes = keyTabFileBytes;
    }

    public boolean isKeyTabUploaded() {
        return (keyTabFilename != null && keyTabFileBytes != null);
    }
    
    public UploadedFile getKrb5ConfFile() {
        return krb5ConfFile;
    }

    public void setKrb5ConfFile(UploadedFile krb5ConfFile) {
        this.krb5ConfFile = krb5ConfFile;
    }

    public String getKrb5ConfFilename() {
        return krb5ConfFilename;
    }

    public void setKrb5ConfFilename(String krb5ConfFilename) {
        this.krb5ConfFilename = StringTools.stripFilename(krb5ConfFilename);
    }

    public byte[] getKrb5ConfFileContent() {
        return krb5ConfFileBytes;
    }

    public void setKrb5ConfFileContent(byte[] krb5ConfFileBytes) {
        this.krb5ConfFileBytes = krb5ConfFileBytes;
    }

    public boolean isKrb5ConfFileUploaded() {
        return (krb5ConfFilename != null && krb5ConfFileBytes != null);
    }
    

    // MSAE Settings
    public boolean isUseSSL() {
        return isUseSSL;
    }

    public void setUseSSL(final boolean isUseSSL) {
        this.isUseSSL = isUseSSL;
    }

    public boolean isFollowLdapReferral() {
        return followLdapReferral;
    }

    public void setFollowLdapReferral(final boolean followLdapReferral) {
        this.followLdapReferral = followLdapReferral;
    }

    public int getAdConnectionPort() {
        return adConnectionPort;
    }

    public void setAdConnectionPort(int adConnectionPort) {
        this.adConnectionPort = adConnectionPort;
    }
    
    public int getLdapReadTimeout() {
        return ldapReadTimeout;
    }

    public void setLdapReadTimeout(final int ldapReadTimeout) {
        this.ldapReadTimeout = ldapReadTimeout;
    }
    
    public int getLdapConnectTimeout() {
        return ldapConnectTimeout;
    }

    public void setLdapConnectTimeout(final int ldapConnectTimeout) {
        this.ldapConnectTimeout = ldapConnectTimeout;
    }

    public String getAdLoginDN() {
        return adLoginDN;
    }

    public void setAdLoginDN(String adLoginDN) {
        this.adLoginDN = adLoginDN;
    }

    public String getAdLoginPassword() {
        return adLoginPassword;
    }

    public void setAdLoginPassword(String adLoginPassword) {
        this.adLoginPassword = adLoginPassword;
    }

    public Integer getAuthKeyBinding() {
        return authKeyBinding;
    }

    public void setAuthKeyBinding(Integer authKeyBinding) {
        this.authKeyBinding = authKeyBinding;
    }

    // MS Servlet Settings
    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    // MS Template Settings
    public List<MSAutoEnrollmentSettingsTemplate> getMappedMsTemplates() {
        return mappedMsTemplates;
    }

    // UI Related Getters and Setters
    public String getSelectedTemplateOid() {
        return selectedTemplateOid;
    }

    public void setSelectedTemplateOid(String selectedTemplateOid) {
        this.selectedTemplateOid = selectedTemplateOid;
    }

    public String getSelectedCertificateProfileName() {
        return selectedCertificateProfileName;
    }

    public void setSelectedCertificateProfileName(String selectedCertificateProfileName) {
        this.selectedCertificateProfileName = selectedCertificateProfileName;
    }

    public Integer getSelectedCertificateProfileId() {
        return selectedCertificateProfileId;
    }

    public void setSelectedCertificateProfileId(Integer selectedCertificateProfileId) {
        if (selectedCertificateProfileId != -1) {
            this.selectedCertificateProfileId = selectedCertificateProfileId;
            setSelectedCertificateProfileName(authorizedCertificateProfiles.get(getSelectedCertificateProfileId()).getName());
        }
    }

    public String getSelectedEndEntityProfileName() {
        return selectedEndEntityProfileName;
    }

    public void setSelectedEndEntityProfileName(String selectedEndEntityProfileName) {
        this.selectedEndEntityProfileName = selectedEndEntityProfileName;
    }

    public Integer getSelectedEndEntityProfileId() {
        return selectedEndEntityProfileId;
    }

    public void setSelectedEndEntityProfileId(Integer selectedEndEntityProfileId) {
        if (selectedEndEntityProfileId != -1) {
            this.selectedEndEntityProfileId = selectedEndEntityProfileId;
            setSelectedEndEntityProfileName(authorizedEndEntityProfiles.get(getSelectedEndEntityProfileId()).getName());
        }
    }

    /**
     * Return the mapped templates in ListDataModel
     *
     * @return template models
     */
    public ListDataModel<MSAutoEnrollmentSettingsTemplate> getMappedMsTemplatesModel() {
        if (mappedMsTemplatesModel == null) {
            mappedMsTemplatesModel = new ListDataModel<>(getMappedMsTemplates());
        }

        return mappedMsTemplatesModel;
    }

    public void removeMappedMSTemplate(){
        // Selected model
        MSAutoEnrollmentSettingsTemplate templateToRemove = mappedMsTemplatesModel.getRowData();

        removeMappedMSTemplate(templateToRemove);
    }

    /**
     * Remove the template from mapped templates and re-create the model list.
     *
     * @param template MS template
     */
    private void removeMappedMSTemplate(MSAutoEnrollmentSettingsTemplate template) {
        mappedMsTemplates.remove(template);
        mappedMsTemplatesModel = new ListDataModel<>(getMappedMsTemplates());
    }

    public void addToMappedMsTemplates() {
        // If a template is already mapped, it should be removed first.
        if (findMsTemplateByOid(mappedMsTemplates, selectedTemplateOid) != null) {
            addErrorMessage("MSAE_ERROR_TEMPLATE_ALREADY_ADDED");
            return;
        }

        if (selectedTemplateOid.equals(SELECT_MST)) {
            addErrorMessage("MSAE_ERROR_TEMPLATE");
            return;
        }

        if (getSelectedCertificateProfileId() == null || getSelectedCertificateProfileId() == -1 || getSelectedCertificateProfileName() == null) {
            addErrorMessage("MSAE_ERROR_CEP");
            return;
        }

        if (getSelectedEndEntityProfileId() == null || getSelectedEndEntityProfileId() == -1 || getSelectedEndEntityProfileName() == null) {
            addErrorMessage("MSAE_ERROR_EEP");
            return;
        }

        addToMappedMsTemplates(selectedTemplateOid, getSelectedCertificateProfileName(), getSelectedEndEntityProfileName());
    }

    /**
     * Map the given template with certificate profile and end entity profile names and
     * add to the mappedTemplates.
     *
     * @param templateOid ms template oid
     * @param certProfile certificate profile name
     * @param eep end entity profile name
     */
    private void addToMappedMsTemplates(final String templateOid, final String certProfile, final String eep) {
        List<MSAutoEnrollmentSettingsTemplate> adTemplates = getAvailableTemplateSettingsFromAD();
        MSAutoEnrollmentSettingsTemplate template = findMsTemplateByOid(adTemplates, templateOid);

        if (template != null) {
            template.setCertificateProfile(certProfile);
            template.setEndEntityProfile(eep);
            mappedMsTemplates.add(template);
            mappedMsTemplatesModel = new ListDataModel<>(getMappedMsTemplates());
        } else {
            addErrorMessage("MSAE_TEMPLATE_NOT_FOUND");
        }
    }

    /**
     * Find and return the template using the oid.
     *
     * @param templates list of MSAutoEnrollmentSettingsTemplate
     * @param templateOid template oid
     * @return
     */
    private MSAutoEnrollmentSettingsTemplate findMsTemplateByOid(List<MSAutoEnrollmentSettingsTemplate> templates, final String templateOid) {
        for (MSAutoEnrollmentSettingsTemplate template: templates) {
            if (template.getOid().equals(templateOid)) {
                return template;
            }
        }

        return null;
    }

    /**
     * Return available MS Templates from Active Directory.
     *
     * @return
     */
    public List<MSAutoEnrollmentSettingsTemplate> getAvailableTemplateSettingsFromAD() {
        // TODO: Implement and maybe return a Map<id, template> so findMsTemplateByOid is simpler
        if (availableTemplates == null) {
            availableTemplates = adConnection.getCertificateTemplateSettings(autoenrollmentConfigMBean.getSelectedAlias());
        }
        return availableTemplates;
    }

    public List<SelectItem> getAvailableTemplates() {
        List<SelectItem> templatesAvailable = new ArrayList<>();
        templatesAvailable.add(new SelectItem(SELECT_MST));

        getAvailableTemplateSettingsFromAD().stream()
                .sorted((template1, template2) -> template1.getDisplayName().toString().compareTo(template2.getDisplayName().toString()))
                .map(template -> new SelectItem(template.getOid(), template.getDisplayName())).forEach(item -> templatesAvailable.add(item));

        return templatesAvailable;
    }

    /**
     * Return the available Certificate Profile id and names based on selected End Entity Profile.
     *
     * @return
     */
    public List<SelectItem> getAvailableCertificateProfiles() {
        List<SelectItem> availableCertificateProfiles = new ArrayList<>();
        availableCertificateProfiles.add(new SelectItem(-1, SELECT_CEP));

        if (getSelectedEndEntityProfileId() != null) {
            EndEntityProfile eep = authorizedEndEntityProfiles.getValue(getSelectedEndEntityProfileId());

            if (eep != null) {
                for (Integer certProfileId: eep.getAvailableCertificateProfileIds()) {
                    if(authorizedCertificateProfiles.containsKey(certProfileId)) {
                        final String certProfileName = authorizedCertificateProfiles.get(certProfileId).getName();
                        availableCertificateProfiles.add(new SelectItem(certProfileId, certProfileName));
                    }
                }
            }
        }
        return availableCertificateProfiles;
    }


    /**
     * Return the available End Entity Profile id and names.
     *
     * @return
     */
    public List<SelectItem> getAvailableEndEntityProfiles() {
        List<SelectItem> availableEndEntityProfiles = new ArrayList<>();
        availableEndEntityProfiles.add(new SelectItem(-1, SELECT_EEP));

        for (final Integer id : authorizedEndEntityProfiles.idKeySet()) {
            availableEndEntityProfiles.add(new SelectItem(String.valueOf(id), authorizedEndEntityProfiles.get(id).getName()));
        }        

        return availableEndEntityProfiles;
    }
    
    public List<SelectItem> getAvailableAuthenticationKeyBindings() {
        final List<SelectItem> ret = new ArrayList<>();
        final List<InternalKeyBindingInfo> authorizedAkbs = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAdmin(), AuthenticationKeyBinding.IMPLEMENTATION_ALIAS);
        for (final InternalKeyBindingInfo current : authorizedAkbs) {
            ret.add(new SelectItem(current.getId(), current.getName(), current.getName(), !current.getStatus().equals(InternalKeyBindingStatus.ACTIVE)));
        }
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
    
    /**
     * Import and save key tab file.
     *
     * @throws IOException
     */
    public void importKeyTabFile() throws IOException {
        if (keyTabFile != null) {
            String contentType = keyTabFile.getContentType();

            if(!contentType.equals(KEYTAB_CONTENT_TYPE)) {
                addErrorMessage("MSAE_KEYTAB_ERROR_WRONG_CONTENT");
                return;
            }

            setKeyTabFilename(keyTabFile.getName());
            setKeyTabFileBytes(keyTabFile.getBytes());

            saveKeyTabFile();
        } else {
            addErrorMessage("MSAE_KEYTAB_ERROR_NOT_FOUND");
        }
    }
    
    /**
     * Import and save krb5 conf file.
     *
     * @throws IOException
     */
    public void importKrb5ConfFile() throws IOException {
        if (krb5ConfFile != null) {
            String contentType = krb5ConfFile.getContentType();

            if(!contentType.equals(KRB5_CONF_CONTENT_TYPE)) {
                addErrorMessage("MSAE_KRB5_CONF_ERROR_WRONG_CONTENT");
                return;
            }
            
            setKrb5ConfFilename(krb5ConfFile.getName());
            setKrb5ConfFileContent(krb5ConfFile.getBytes());

            saveKrb5ConfFile();
        } else {
            addErrorMessage("MSAE_KRB5_CONF_ERROR_NOT_FOUND");
        }
        
    }

    /**
     * Download save key tab file from UI.
     *
     */
    public void downloadKeyTabFile() {
        if (keyTabFileBytes != null && keyTabFilename != null) {

            FacesContext fc = FacesContext.getCurrentInstance();
            ExternalContext ec = fc.getExternalContext();
            ec.responseReset();
            ec.setResponseContentType(KEYTAB_CONTENT_TYPE);
            ec.setResponseContentLength(keyTabFileBytes.length);

            final String filename = "keytab.krb";
            ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            try (OutputStream output = ec.getResponseOutputStream()) {
                output.write(keyTabFileBytes);
                output.flush();
                fc.responseComplete();
            } catch (IOException e) {
                log.info("Key Tab " + filename + " could not be downloaded", e);
                addErrorMessage("MSAE_KEYTAB_ERROR_COULD_NOT_BE_DOWNLOADED");
            }
        } else {
            addErrorMessage("MSAE_KEYTAB_ERROR_COULD_NOT_BE_DOWNLOADED");
        }
    }
    
    /**
     * Download save krb5 conf file from UI.
     *
     */
    public void downloadKrb5ConfFile() {
        if (krb5ConfFileBytes != null && krb5ConfFilename != null) {

            FacesContext fc = FacesContext.getCurrentInstance();
            ExternalContext ec = fc.getExternalContext();
            ec.responseReset();
            ec.setResponseContentType(KRB5_CONF_CONTENT_TYPE);
            ec.setResponseContentLength(krb5ConfFileBytes.length);

            final String filename = "krb5.conf";
            ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            try (OutputStream output = ec.getResponseOutputStream()) {
                output.write(krb5ConfFileBytes);
                output.flush();
                fc.responseComplete();
            } catch (IOException e) {
                log.warn("Krb5 Conf " + filename + " could not be downloaded", e);
                addErrorMessage("MSAE_KRB5_CONF_ERROR_COULD_NOT_BE_DOWNLOADED");
                throw new IllegalStateException("Failed to close outputstream", e);
            }
        } else {
            addErrorMessage("MSAE_KEYTAB_ERROR_COULD_NOT_BE_DOWNLOADED");
        }
    }

    /**
     * Test if a connection can be made to Active Directory with given credentials.
     */
    public void testAdConnection() {
        String adLoginPass = getAdLoginPassword();
        if (StringUtils.isBlank(getAdLoginDN())) {
            addErrorMessage("MSAE_AD_TEST_CONNECTION_ERROR_NO_LOGIN");
            return;
        }
        if (StringUtils.isBlank(adLoginPass)) {
            addErrorMessage("MSAE_AD_TEST_CONNECTION_ERROR_NO_PWD");
            return;
        }
        if (adLoginPass.equals(HIDDEN_PWD)) {
            // If password field has been reset in GUI, test connection with persisted password
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);
            adLoginPass = autoEnrollmentConfiguration.getAdLoginPassword(autoenrollmentConfigMBean.getSelectedAlias());
            if (StringUtils.isEmpty(adLoginPass)) {
                addErrorMessage("MSAE_AD_TEST_CONNECTION_FAILURE", "Invalid Credentials");
                return;
            }
        }
        try {
            availableTemplates = null;
            adConnection.testConnection(getMsaeDomain(), getAdConnectionPort(), getAdLoginDN(), adLoginPass, isUseSSL(), isFollowLdapReferral(),
                    getLdapReadTimeout(), getLdapConnectTimeout(), autoenrollmentConfigMBean.getSelectedAlias());
            addInfoMessage("MSAE_AD_TEST_CONNECTION_SUCCESS");
        } catch (LDAPException e) {
            addErrorMessage("MSAE_AD_TEST_CONNECTION_FAILURE", e.getFriendlyMessage());
            return;
        }
        // Save if connection was successful (in order to render templates without a page reload)
        save();
    }

    /**
     * Save key tab to the global configuration.
     */
    public void saveKeyTabFile() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            autoEnrollmentConfiguration.setMsaeKeyTabFilename(autoenrollmentConfigMBean.getSelectedAlias(), getKeyTabFilename());
            autoEnrollmentConfiguration.setMsaeKeyTabBytes(autoenrollmentConfigMBean.getSelectedAlias(), getKeyTabFileBytes());

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("MSAE_KEYTAB_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment Key Tab because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("MSAE_KEYTAB_SAVE_ERROR");
        }
    }
    
    
    /**
     * Save krb5 conf to the global configuration.
     */
    public void saveKrb5ConfFile() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            autoEnrollmentConfiguration.setMsaeKrb5ConfFilename(autoenrollmentConfigMBean.getSelectedAlias(), getKrb5ConfFilename());
            autoEnrollmentConfiguration.setMsaeKrb5ConfBytes(autoenrollmentConfigMBean.getSelectedAlias(), getKrb5ConfFileContent());

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("MSAE_KRB5_CONF_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment Krb5 conf file because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("MSAE_KRB5_CONF_SAVE_ERROR");
        }
    }

    // Updates persisted template mappings with new values from AD
    public void updateMappedTemplates() {
        // Force reload from AD
        availableTemplates = null;
        List<MSAutoEnrollmentSettingsTemplate> newTemplates = getAvailableTemplateSettingsFromAD();
        for (MSAutoEnrollmentSettingsTemplate persistedTemplate : mappedMsTemplates) {
            MSAutoEnrollmentSettingsTemplate newTemplateSettings = findMsTemplateByOid(newTemplates, persistedTemplate.getOid());
            if (newTemplateSettings == null) {
                return;
            }
            persistedTemplate.setDisplayName(newTemplateSettings.getDisplayName());
            persistedTemplate.setName(newTemplateSettings.getName());
            persistedTemplate.setMinorRevision(newTemplateSettings.getMinorRevision());
            persistedTemplate.setMajorRevision(newTemplateSettings.getMajorRevision());
            persistedTemplate.setAdditionalSubjectDNAttributes(newTemplateSettings.getAdditionalSubjectDNAttributes());
            persistedTemplate.setSubjectNameFormat(newTemplateSettings.getSubjectNameFormat());
            persistedTemplate.setIncludeDomainInSubjectSAN(newTemplateSettings.isIncludeDomainInSubjectSAN());
            persistedTemplate.setIncludeEmailInSubjectDN(newTemplateSettings.isIncludeEmailInSubjectDN());
            persistedTemplate.setIncludeEmailInSubjectSAN(newTemplateSettings.isIncludeEmailInSubjectSAN());
            persistedTemplate.setIncludeNetBiosInSubjectSAN(newTemplateSettings.isIncludeNetBiosInSubjectSAN());
            persistedTemplate.setIncludeObjectGuidInSubjectSAN(newTemplateSettings.isIncludeObjectGuidInSubjectSAN());
            persistedTemplate.setIncludeSPNInSubjectSAN(newTemplateSettings.isIncludeSPNInSubjectSAN());
            persistedTemplate.setIncludeUPNInSubjectSAN(newTemplateSettings.isIncludeUPNInSubjectSAN());
            persistedTemplate.setPublishToActiveDirectory(newTemplateSettings.isPublishToActiveDirectory());
        }
    }
    
    public void save() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            // MSAE Kerberos Settings
            autoEnrollmentConfiguration.setMsaeForestRoot(autoenrollmentConfigMBean.getSelectedAlias(), msaeForestRoot);
            autoEnrollmentConfiguration.setMsaeDomain(autoenrollmentConfigMBean.getSelectedAlias(), msaeDomain);
            autoEnrollmentConfiguration.setPolicyName(autoenrollmentConfigMBean.getSelectedAlias(), policyName);
            autoEnrollmentConfiguration.setPolicyUid(autoenrollmentConfigMBean.getSelectedAlias());
            autoEnrollmentConfiguration.setSpn(autoenrollmentConfigMBean.getSelectedAlias(), servicePrincipalName);

            // MSAE Settings
            autoEnrollmentConfiguration.setIsUseSsl(autoenrollmentConfigMBean.getSelectedAlias(), isUseSSL);
            autoEnrollmentConfiguration.setFollowLdapReferral(autoenrollmentConfigMBean.getSelectedAlias(), followLdapReferral);
            autoEnrollmentConfiguration.setAdConnectionPort(autoenrollmentConfigMBean.getSelectedAlias(), adConnectionPort);
            autoEnrollmentConfiguration.setLdapReadTimeout(autoenrollmentConfigMBean.getSelectedAlias(), ldapReadTimeout);
            autoEnrollmentConfiguration.setLdapConnectTimeout(autoenrollmentConfigMBean.getSelectedAlias(), ldapConnectTimeout);
            
            autoEnrollmentConfiguration.setAdLoginDN(autoenrollmentConfigMBean.getSelectedAlias(), adLoginDN);
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!adLoginPassword.equals(MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD)) {
                autoEnrollmentConfiguration.setAdLoginPassword(autoenrollmentConfigMBean.getSelectedAlias(), adLoginPassword);
                adLoginPassword = MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD;
            }

            autoEnrollmentConfiguration.setAuthKeyBinding(autoenrollmentConfigMBean.getSelectedAlias(), authKeyBinding);

            // MS Servlet Settings
            autoEnrollmentConfiguration.setCaName(autoenrollmentConfigMBean.getSelectedAlias(), caName);

            // MS Template Settings
            updateMappedTemplates();
            autoEnrollmentConfiguration.setMsTemplateSettings(autoenrollmentConfigMBean.getSelectedAlias(), mappedMsTemplates);

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("MSAE_AUTOENROLLMENT_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("MSAE_AUTOENROLLMENT_SAVE_ERROR");
        }
    }

    public String cancel() {
        reset();
        return "done";
    }
    
    private void reset() {
        getEjbcaWebBean().clearAutoenrollConfigClone();
        autoenrollmentConfigMBean.actionCancel();
    }
    
    public AutoenrollmentConfigMBean getAutoenrollmentConfigMBean() {
        return autoenrollmentConfigMBean;
    }

    public void setAutoenrollmentConfigMBean(AutoenrollmentConfigMBean autoenrollmentConfigMBean) {
        this.autoenrollmentConfigMBean = autoenrollmentConfigMBean;
    }
    
}
