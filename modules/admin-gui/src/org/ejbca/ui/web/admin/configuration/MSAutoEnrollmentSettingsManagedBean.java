package org.ejbca.ui.web.admin.configuration;

import org.apache.log4j.Logger;
import org.apache.myfaces.custom.fileupload.UploadedFile;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.StringTools;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Backing bean for MSAutoEnrollmentConfiguration in System Settings.
 */
@ManagedBean(name = "msAutoEnrollmentSettings")
@ViewScoped
public class MSAutoEnrollmentSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(MSAutoEnrollmentSettingsManagedBean.class);
    private static final long serialVersionUID = 1L;

    private static final String SELECT_CEP = "Select a Certificate Profile";
    private static final String SELECT_EEP = "Select an End Entity Profile";
    private static final String SELECT_MST = "Select a Template";
    private static final String KEYTAB_CONTENT_TYPE = "application/octet-stream";

    // MSAE Kerberos Settings
    private String msaeDomain;
    private UploadedFile keyTabFile;
    private String keyTabFilename;
    private byte[] keyTabFileBytes;

    // MSAE Settings
    private boolean isUseSSL;
    private int adConnectionPort;
    private String adLoginDN;
    private String adLoginPassword;

    // MS Servlet Settings
    private String keyStorePath;
    private String keyStorePassword;
    private String trustedKeyStorePath;
    private String trustedKeyStorePassword;
    private String caName;

    // MS Template Settings: Holds mapped MS Templates for the configuration
    private List<MSAutoEnrollmentSettingsTemplate> mappedMsTemplates;
    private ListDataModel<MSAutoEnrollmentSettingsTemplate> mappedMsTemplatesModel;

    private String selectedTemplateName;
    private String selectedCertificationProfileName;
    private Integer selectedCertificationProfileId;
    private String selectedEndEntityProfileName;

    private final CertificateProfileSessionLocal certificateProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final EndEntityProfileSessionLocal endEntityProfileSession = getEjbcaWebBean().getEjb().getEndEntityProfileSession();

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {

        final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

        if (autoEnrollmentConfiguration != null) {
            msaeDomain = autoEnrollmentConfiguration.getMsaeDomain();
            keyTabFileBytes = autoEnrollmentConfiguration.getMsaeKeyTabBytes();
            keyTabFilename = autoEnrollmentConfiguration.getMsaeKeyTabFilename();

            isUseSSL = autoEnrollmentConfiguration.isUseSSL();
            adConnectionPort = autoEnrollmentConfiguration.getADConnectionPort();
            adLoginDN = autoEnrollmentConfiguration.getAdLoginDN();
            adLoginPassword = autoEnrollmentConfiguration.getAdLoginPassword();

            keyStorePath = autoEnrollmentConfiguration.getKeyStorePath();
            keyStorePassword = autoEnrollmentConfiguration.getKeyStorePassword();
            trustedKeyStorePath = autoEnrollmentConfiguration.getTrustedKeyStorePath();
            trustedKeyStorePassword = autoEnrollmentConfiguration.getTrustedKeyStorePassword();
            caName = autoEnrollmentConfiguration.getCaName();

            mappedMsTemplates = autoEnrollmentConfiguration.getMsTemplateSettings();
        }
    }

    // MSAE Kerberos Settings
    public String getMsaeDomain() {
        return msaeDomain;
    }

    public void setMsaeDomain(String msaeDomain) {
        this.msaeDomain = msaeDomain;
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

    // MSAE Settings
    public boolean isUseSSL() {
        return isUseSSL;
    }

    public void setUseSSL(final boolean isUseSSL) {
        this.isUseSSL = isUseSSL;
    }

    public int getAdConnectionPort() {
        return adConnectionPort;
    }

    public void setAdConnectionPort(int adConnectionPort) {
        this.adConnectionPort = adConnectionPort;
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

    // MS Servlet Settings
    public String getKeyStorePath() {
        return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getTrustedKeyStorePath() {
        return trustedKeyStorePath;
    }

    public void setTrustedKeyStorePath(String trustedKeyStorePath) {
        this.trustedKeyStorePath = trustedKeyStorePath;
    }

    public String getTrustedKeyStorePassword() {
        return trustedKeyStorePassword;
    }

    public void setTrustedKeyStorePassword(String trustedKeyStorePassword) {
        this.trustedKeyStorePassword = trustedKeyStorePassword;
    }

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
    public String getSelectedTemplateName() {
        return selectedTemplateName;
    }

    public void setSelectedTemplateName(String selectedTemplateName) {
        this.selectedTemplateName = selectedTemplateName;
    }

    public String getSelectedCertificationProfileName() {
        return selectedCertificationProfileName;
    }

    public void setSelectedCertificationProfileName(String selectedCertificationProfileName) {
        this.selectedCertificationProfileName = selectedCertificationProfileName;
    }

    public Integer getSelectedCertificationProfileId() {
        return selectedCertificationProfileId;
    }

    public void setSelectedCertificationProfileId(Integer selectedCertificationProfileId) {
        this.selectedCertificationProfileId = selectedCertificationProfileId;
    }

    public String getSelectedEndEntityProfileName() {
        return selectedEndEntityProfileName;
    }

    public void setSelectedEndEntityProfileName(String selectedEndEntityProfileName) {
        this.selectedEndEntityProfileName = selectedEndEntityProfileName;
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
        if (findMsTemplateByOid(mappedMsTemplates, selectedTemplateName) != null) {
            addErrorMessage("MSAE_ERROR_TEMPLATE_ALREADY_ADDED");
            return;
        }

        if (selectedTemplateName.equals(SELECT_MST)) {
            addErrorMessage("MSAE_ERROR_TEMPLATE");
            return;
        }

        if (selectedCertificationProfileId == null || selectedCertificationProfileId == -1) {
            addErrorMessage("MSAE_ERROR_CEP");
            return;
        }

        if (selectedEndEntityProfileName == null || selectedEndEntityProfileName.equals(SELECT_EEP)) {
            addErrorMessage("MSAE_ERROR_EEP");
            return;
        }

        selectedCertificationProfileName = certificateProfileSession.getCertificateProfileName(selectedCertificationProfileId);
        if (selectedCertificationProfileName == null) {
            addErrorMessage("MSAE_ERROR_CEP");
            return;
        }

        addToMappedMsTemplates(selectedTemplateName, selectedEndEntityProfileName, selectedCertificationProfileName);
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
            template.setCertificationProfile(certProfile);
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
        // TODO: Implement
        List<MSAutoEnrollmentSettingsTemplate> templates = new ArrayList<>();

        MSAutoEnrollmentSettingsTemplate oid1 = new MSAutoEnrollmentSettingsTemplate();
        oid1.setOid("Template 1");
        templates.add(oid1);

        MSAutoEnrollmentSettingsTemplate oid2 = new MSAutoEnrollmentSettingsTemplate();
        oid2.setOid("Template 2");
        templates.add(oid2);

        MSAutoEnrollmentSettingsTemplate oid3 = new MSAutoEnrollmentSettingsTemplate();
        oid3.setOid("Template 3");
        templates.add(oid3);

        return templates;
    }

    public List<SelectItem> getAvailableTemplateOids() {
        List<SelectItem> availableTemplateOids = new ArrayList<>();
        availableTemplateOids.add(new SelectItem(SELECT_MST));

        for (MSAutoEnrollmentSettingsTemplate template: getAvailableTemplateSettingsFromAD()) {
            availableTemplateOids.add(new SelectItem(template.getOid()));
        }

        return availableTemplateOids;
    }

    /**
     * Return a list of certificate profile id and names.
     *
     * @return
     */
    public List<SelectItem> getAvailableCertificateProfiles() {
        List<SelectItem> availableCertificateProfiles = new ArrayList<>();
        availableCertificateProfiles.add(new SelectItem(-1, SELECT_CEP));

        for (final Map.Entry<String,Integer> entry : getAllCertificateProfiles().entrySet()) {
            final int certProfileId = entry.getValue(); // map is inverted
            final String certProfileName = entry.getKey();
            availableCertificateProfiles.add(new SelectItem(certProfileId, certProfileName));
        }

        return availableCertificateProfiles;
    }

    /**
     * Return all authorized Certificate Profile names.
     *
     * @return
     */
    private TreeMap<String, Integer> getAllCertificateProfiles() {
        final TreeMap<String, Integer> eecertificateprofilenames = getEjbcaWebBean().getAuthorizedEndEntityCertificateProfileNames();
        final TreeMap<String, Integer> subcacertificateprofilenames = getEjbcaWebBean().getAuthorizedSubCACertificateProfileNames();
        final TreeMap<String, Integer> sshcertificateprofilenames = getEjbcaWebBean().getAuthorizedSshCertificateProfileNames();
        final TreeMap<String, Integer> mergedMap = new TreeMap<>();

        mergedMap.putAll(eecertificateprofilenames);
        mergedMap.putAll(subcacertificateprofilenames);
        mergedMap.putAll(sshcertificateprofilenames);

        return mergedMap;
    }

    /**
     * Return the available EEP names based on the selected Certificate Profile id.
     *
     * @return
     */
    public List<SelectItem> getAvailableEndEntityProfiles() {
        List<SelectItem> availableEndEntityProfiles = new ArrayList<>();
        availableEndEntityProfiles.add(new SelectItem(SELECT_EEP));

        if (selectedCertificationProfileId != null){
            List<String> eepNames = endEntityProfileSession.getEndEntityProfilesUsingCertificateProfile(selectedCertificationProfileId);
            for (String eepName: eepNames) {
                availableEndEntityProfiles.add(new SelectItem(eepName));
            }
        }

        return availableEndEntityProfiles;
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

            OutputStream output = null;
            try {
                output = ec.getResponseOutputStream();
                output.write(keyTabFileBytes);
                output.flush();
                fc.responseComplete();
            } catch (IOException e) {
                log.info("Key Tab " + filename + " could not be downloaded", e);
                addErrorMessage("MSAE_KEYTAB_ERROR_COULD_NOT_BE_DOWNLOADED");
            } finally {
                if (output != null) {
                    try {
                        output.close();
                    } catch (IOException e) {
                        throw new IllegalStateException("Failed to close outputstream", e);
                    }
                }
            }
        } else {
            addErrorMessage("MSAE_KEYTAB_ERROR_COULD_NOT_BE_DOWNLOADED");
        }
    }

    /**
     * Save key tab to the global configuration.
     */
    public void saveKeyTabFile() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            autoEnrollmentConfiguration.setMsaeKeyTabFilename(getKeyTabFilename());
            autoEnrollmentConfiguration.setMsaeKeyTabBytes(getKeyTabFileBytes());

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("MSAE_KEYTAB_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment Key Tab because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("MSAE_KEYTAB_SAVE_ERROR");
        }
    }

    public void save() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            // MSAE Kerberos Settings
            autoEnrollmentConfiguration.setMsaeDomain(msaeDomain);

            // MSAE Settings
            autoEnrollmentConfiguration.setIsUseSsl(isUseSSL);
            autoEnrollmentConfiguration.setAdConnectionPort(adConnectionPort);
            autoEnrollmentConfiguration.setAdLoginDN(adLoginDN);
            autoEnrollmentConfiguration.setAdLoginPassword(adLoginPassword);

            // MS Servlet Settings
            autoEnrollmentConfiguration.setKeyStorePath(keyStorePath);
            autoEnrollmentConfiguration.setKeyStorePassword(keyStorePassword);
            autoEnrollmentConfiguration.setTrustedKeyStorePath(trustedKeyStorePath);
            autoEnrollmentConfiguration.setTrustedKeyStorePassword(trustedKeyStorePassword);
            autoEnrollmentConfiguration.setCaName(caName);

            // MS Template Settings
            autoEnrollmentConfiguration.setMsTemplateSettings(mappedMsTemplates);

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("MSAE_AUTOENROLLMENT_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("MSAE_AUTOENROLLMENT_SAVE_ERROR");
        }
    }
}
