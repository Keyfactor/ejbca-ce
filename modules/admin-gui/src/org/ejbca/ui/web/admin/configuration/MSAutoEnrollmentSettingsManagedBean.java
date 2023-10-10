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

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.msae.ADConnectionSingletonLocal;
import org.ejbca.core.protocol.msae.LDAPException;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.Part;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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

    public static final String HIDDEN_PWD = "**********";

    private static final String SELECT_CEP = "Select a Certificate Profile";
    private static final String SELECT_EEP = "Select an End Entity Profile";
    private static final String SELECT_MST = "Select a Template";
    private static final String KEYTAB_CONTENT_TYPE = "application/octet-stream";
    private static final String KRB5_CONF_CONTENT_TYPE = "application/octet-stream";
    private static final String KRB5_CONF_CONTENT_TYPE_PLAIN = "text/plain";
    private Part keyTabFile;

    // MSAE Krb5Conf Settings
    private Part krb5ConfFile;
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

    private AutoEnrollmentDTO dto;

    @PostConstruct
    public void loadConfiguration() {
        this.authorizedEndEntityProfiles = raMasterApiProxyBean.getAuthorizedEndEntityProfiles(getAdmin(), AccessRulesConstants.CREATE_END_ENTITY);
        this.authorizedCertificateProfiles = raMasterApiProxyBean.getAuthorizedCertificateProfiles(getAdmin());
    }

    public AutoEnrollmentDTO getDto() {
        String aliasName = autoenrollmentConfigMBean.getSelectedAlias();
        if (dto == null) {
            if (StringUtils.isEmpty(aliasName)) {
                this.dto = new AutoEnrollmentDTO();
            } else {
                final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                        globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);
                this.dto = new AutoEnrollmentDTO(aliasName, autoEnrollmentConfiguration);
            }
        }
        return dto;
    }

    public void setDto(AutoEnrollmentDTO dto) {
        this.dto = dto;
    }


    public Part getKeyTabFile() {
        return keyTabFile;
    }

    public void setKeyTabFile(Part keyTabFile) {
        this.keyTabFile = keyTabFile;
    }

    public boolean isKeyTabUploaded() {
        return (getDto().getKeyTabFilename() != null && getDto().getKeyTabFileBytes() != null);
    }

    public Part getKrb5ConfFile() {
        return krb5ConfFile;
    }

    public void setKrb5ConfFile(Part krb5ConfFile) {
        this.krb5ConfFile = krb5ConfFile;
    }

    public boolean isKrb5ConfFileUploaded() {
        return (getDto().getKrb5ConfFilename() != null && getDto().getKrb5ConfFileBytes() != null);
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
        return new ListDataModel<>(getDto().getMappedMsTemplates());
    }

    public void removeMappedMSTemplate() {
        // Selected model
        MSAutoEnrollmentSettingsTemplate templateToRemove = getMappedMsTemplatesModel().getRowData();
        getDto().getMappedMsTemplates().remove(templateToRemove);
    }

    public void addToMappedMsTemplates() {
        // If a template is already mapped, it should be removed first.
        if (findMsTemplateByOid(getDto().getMappedMsTemplates(), selectedTemplateOid) != null) {
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
     * @param eep         end entity profile name
     */
    private void addToMappedMsTemplates(final String templateOid, final String certProfile, final String eep) {
        List<MSAutoEnrollmentSettingsTemplate> adTemplates = getAvailableTemplateSettingsFromAD();
        MSAutoEnrollmentSettingsTemplate template = findMsTemplateByOid(adTemplates, templateOid);
        if (template != null) {
            template.setCertificateProfile(certProfile);
            template.setEndEntityProfile(eep);
            getDto().getMappedMsTemplates().add(template);
        } else {
            addErrorMessage("MSAE_TEMPLATE_NOT_FOUND");
        }
    }

    /**
     * Find and return the template using the oid.
     *
     * @param templates   list of MSAutoEnrollmentSettingsTemplate
     * @param templateOid template oid
     * @return
     */
    private MSAutoEnrollmentSettingsTemplate findMsTemplateByOid(List<MSAutoEnrollmentSettingsTemplate> templates, final String templateOid) {
        for (MSAutoEnrollmentSettingsTemplate template : templates) {
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
            final String selectedAlias = getDto().getAlias();
            if (selectedAlias == null) {
                return Collections.emptyList();
            }
            availableTemplates = adConnection.getCertificateTemplateSettings(selectedAlias);
        }
        return availableTemplates;
    }

    public List<SelectItem> getAvailableTemplates() {
        return Stream.concat(
                Stream.of(new SelectItem(SELECT_MST)),
                getAvailableTemplateSettingsFromAD().stream()
                        .sorted(Comparator.comparing(MSAutoEnrollmentSettingsTemplate::getDisplayName))
                        .map(template -> new SelectItem(template.getOid(), template.getDisplayName()))
        ).collect(Collectors.toList());

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
                for (Integer certProfileId : eep.getAvailableCertificateProfileIds()) {
                    if (authorizedCertificateProfiles.containsKey(certProfileId)) {
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
        return internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAdmin(), AuthenticationKeyBinding.IMPLEMENTATION_ALIAS).stream()
                .map(current -> new SelectItem(current.getId(), current.getName(), current.getName(), !current.getStatus().equals(InternalKeyBindingStatus.ACTIVE)))
                .collect(Collectors.toList());
    }

    /**
     * @return a list of all CA names and caids
     */
    public List<SelectItem> getAvailableCAs() {
        final List<SelectItem> ret = new ArrayList<>();
        Map<Integer, String> caidToName = caSession.getCAIdToNameMap();
        List<Integer> allCaIds = caSession.getAllCaIds();
        for (int caid : allCaIds) {
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

            if (!contentType.equals(KEYTAB_CONTENT_TYPE)) {
                addErrorMessage("MSAE_KEYTAB_ERROR_WRONG_CONTENT");
                return;
            }

            final byte[] fileBytes = IOUtils.toByteArray(keyTabFile.getInputStream(), keyTabFile.getSize());
            getDto().setKeyTabFilename(keyTabFile.getSubmittedFileName());
            getDto().setKeyTabFileBytes(fileBytes);

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

            if (!(contentType.equals(KRB5_CONF_CONTENT_TYPE) || contentType.equals(KRB5_CONF_CONTENT_TYPE_PLAIN))) {
                addErrorMessage("MSAE_KRB5_CONF_ERROR_WRONG_CONTENT");
                return;
            }
            final byte[] fileBytes = IOUtils.toByteArray(krb5ConfFile.getInputStream(), krb5ConfFile.getSize());
            getDto().setKrb5ConfFilename(krb5ConfFile.getSubmittedFileName());
            getDto().setKrb5ConfFileBytes(fileBytes);

            saveKrb5ConfFile();
        } else {
            addErrorMessage("MSAE_KRB5_CONF_ERROR_NOT_FOUND");
        }

    }

    /**
     * Download save key tab file from UI.
     */
    public void downloadKeyTabFile() {
        if (getDto().getKeyTabFileBytes() != null && getDto().getKeyTabFilename() != null) {

            FacesContext fc = FacesContext.getCurrentInstance();
            ExternalContext ec = fc.getExternalContext();
            ec.responseReset();
            ec.setResponseContentType(KEYTAB_CONTENT_TYPE);
            ec.setResponseContentLength(getDto().getKeyTabFileBytes().length);

            final String filename = "keytab.krb";
            ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            try (OutputStream output = ec.getResponseOutputStream()) {
                output.write(getDto().getKeyTabFileBytes());
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
     */
    public void downloadKrb5ConfFile() {
        if (getDto().getKrb5ConfFileBytes() != null && getDto().getKrb5ConfFilename() != null) {

            FacesContext fc = FacesContext.getCurrentInstance();
            ExternalContext ec = fc.getExternalContext();
            ec.responseReset();
            ec.setResponseContentType(KRB5_CONF_CONTENT_TYPE);
            ec.setResponseContentLength(getDto().getKrb5ConfFileBytes().length);

            final String filename = "krb5.conf";
            ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

            try (OutputStream output = ec.getResponseOutputStream()) {
                output.write(getDto().getKrb5ConfFileBytes());
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
        String adLoginPass = getDto().getAdLoginPassword();
        if (StringUtils.isBlank(getDto().getAdLoginDN())) {
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
            adLoginPass = autoEnrollmentConfiguration.getAdLoginPassword(getDto().getAlias());
            if (StringUtils.isEmpty(adLoginPass)) {
                addErrorMessage("MSAE_AD_TEST_CONNECTION_FAILURE", "Invalid Credentials");
                return;
            }
        }
        try {
            availableTemplates = null;
            adConnection.testConnection(getDto().getMsaeDomain(), getDto().getAdConnectionPort(), getDto().getAdLoginDN(), adLoginPass, getDto().isUseSSL(), getDto().isFollowLdapReferral(),
                    getDto().getLdapReadTimeout(), getDto().getLdapConnectTimeout(), getDto().getAlias());
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

            autoEnrollmentConfiguration.setMsaeKeyTabFilename(getDto().getAlias(), getDto().getKeyTabFilename());
            autoEnrollmentConfiguration.setMsaeKeyTabBytes(getDto().getAlias(), getDto().getKeyTabFileBytes());

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

            autoEnrollmentConfiguration.setMsaeKrb5ConfFilename(getDto().getAlias(), getDto().getKrb5ConfFilename());
            autoEnrollmentConfiguration.setMsaeKrb5ConfBytes(getDto().getAlias(), getDto().getKrb5ConfFileBytes());

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
        for (MSAutoEnrollmentSettingsTemplate persistedTemplate : getDto().getMappedMsTemplates()) {
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
            autoEnrollmentConfiguration.setMsaeForestRoot(getDto().getAlias(), getDto().getMsaeForestRoot());
            autoEnrollmentConfiguration.setMsaeDomain(getDto().getAlias(), getDto().getMsaeDomain());
            autoEnrollmentConfiguration.setPolicyName(getDto().getAlias(), getDto().getPolicyName());
            autoEnrollmentConfiguration.setPolicyUid(getDto().getAlias());
            autoEnrollmentConfiguration.setSpn(getDto().getAlias(), getDto().getServicePrincipalName());

            // MSAE Settings
            autoEnrollmentConfiguration.setIsUseSsl(getDto().getAlias(), getDto().isUseSSL());
            autoEnrollmentConfiguration.setFollowLdapReferral(getDto().getAlias(), getDto().isFollowLdapReferral());
            autoEnrollmentConfiguration.setAdConnectionPort(getDto().getAlias(), getDto().getAdConnectionPort());
            autoEnrollmentConfiguration.setLdapReadTimeout(getDto().getAlias(), getDto().getLdapReadTimeout());
            autoEnrollmentConfiguration.setLdapConnectTimeout(getDto().getAlias(), getDto().getLdapConnectTimeout());

            autoEnrollmentConfiguration.setAdLoginDN(getDto().getAlias(), getDto().getAdLoginDN());
            // If the client secret was not changed from the placeholder value in the UI, set the old value, i.e. no change
            if (!getDto().getAdLoginPassword().equals(MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD)) {
                autoEnrollmentConfiguration.setAdLoginPassword(getDto().getAlias(), getDto().getAdLoginPassword());
                getDto().setAdLoginPassword(MSAutoEnrollmentSettingsManagedBean.HIDDEN_PWD);
            }

            autoEnrollmentConfiguration.setAuthKeyBinding(getDto().getAlias(), getDto().getAuthKeyBinding());

            // MS Servlet Settings
            autoEnrollmentConfiguration.setCaName(getDto().getAlias(), getDto().getCaName());

            // MS Template Settings
            updateMappedTemplates();
            autoEnrollmentConfiguration.setMsTemplateSettings(getDto().getAlias(), getDto().getMappedMsTemplates());

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
