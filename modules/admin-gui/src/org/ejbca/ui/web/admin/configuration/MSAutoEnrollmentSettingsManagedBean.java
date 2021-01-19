package org.ejbca.ui.web.admin.configuration;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.config.MSAutoEnrollmentOIDInfo;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Backing bean for MSAutoEnrollmentConfiguration in System Settings.
 */
@ManagedBean(name = "msAutoEnrollmentSettings")
@ViewScoped
public class MSAutoEnrollmentSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(MSAutoEnrollmentSettingsManagedBean.class);
    private static final long serialVersionUID = 1L;

    private static String SELECT_CEP = "Select a Certificate Profile";
    private static String SELECT_EEP = "Select an End Entity Profile";
    private static String SELECT_MST = "Select a Template";

    // MSAE Kerberos Settings
    private String msaeDomain;

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

    // MS Template Settings
    private List<MSAutoEnrollmentOIDInfo> msTemplateSettings;
    private ListDataModel<MSAutoEnrollmentOIDInfo> msTemplateSettingsModel;

    private String selectedTemplateSettingOID;
    private String selectedCertificationProfile;
    private Integer selectedCertificationProfileId;
    private String selectedEndEntityProfile;

    private List<SelectItem> availableTemplateSettingOIDs;
    private List<SelectItem> availableCertificationProfiles;
    private List<SelectItem> availableEndEntityProfiles;

    private final CertificateProfileSessionLocal certificateProfileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
    private final EndEntityProfileSessionLocal endEntityProfileSession = getEjbcaWebBean().getEjb().getEndEntityProfileSession();

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {

        final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

        // Get values
        if (autoEnrollmentConfiguration != null) {
            msaeDomain = autoEnrollmentConfiguration.getMsaeDomain();

            isUseSSL = autoEnrollmentConfiguration.isUseSSL();
            adConnectionPort = autoEnrollmentConfiguration.getADConnectionPort();
            adLoginDN = autoEnrollmentConfiguration.getAdLoginDN();
            adLoginPassword = autoEnrollmentConfiguration.getAdLoginPassword();

            keyStorePath = autoEnrollmentConfiguration.getKeyStorePath();
            keyStorePassword = autoEnrollmentConfiguration.getKeyStorePassword();
            trustedKeyStorePath = autoEnrollmentConfiguration.getTrustedKeyStorePath();
            trustedKeyStorePassword = autoEnrollmentConfiguration.getTrustedKeyStorePassword();
            caName = autoEnrollmentConfiguration.getCaName();

            msTemplateSettings = autoEnrollmentConfiguration.getMsTemplateSettings();
        }
    }

    //TODO: Remove
    private void addRandomOID(){
        MSAutoEnrollmentOIDInfo oid = new MSAutoEnrollmentOIDInfo();
        oid.setOid("OID" + System.nanoTime());
        oid.setCertificationProfile("CEP " + System.nanoTime());
        oid.setEndEntityProfile("EEP " + System.nanoTime());

        msTemplateSettings.add(oid);
    }

    // MSAE Kerberos Settings
    public String getMsaeDomain() {
        return msaeDomain;
    }

    public void setMsaeDomain(String msaeDomain) {
        this.msaeDomain = msaeDomain;
    }

    // MSAE SETTINGS
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
    public List<MSAutoEnrollmentOIDInfo> getMsTemplateSettings() {
        return msTemplateSettings;
    }

    public ListDataModel<MSAutoEnrollmentOIDInfo> getMsTemplateSettingsModel() {
        if (msTemplateSettingsModel == null) {
            msTemplateSettingsModel = new ListDataModel<>(getMsTemplateSettings());
        }

        return msTemplateSettingsModel;
    }

    public void setMsTemplateSettings(List<MSAutoEnrollmentOIDInfo> msTemplateSettings) {
        this.msTemplateSettings = msTemplateSettings;
    }

    public void removeMsTemplateSettingFromModel(){
        MSAutoEnrollmentOIDInfo templateToRemove = msTemplateSettingsModel.getRowData();
        removeMsTemplateSettings(templateToRemove);
    }

    public void removeMsTemplateSettings(MSAutoEnrollmentOIDInfo oidInfo) {
        msTemplateSettings.remove(oidInfo);
        msTemplateSettingsModel = new ListDataModel<>(getMsTemplateSettings());
    }

    public void addMsTemplateSettingToModel() {
        // If a template is already mapped, it should be removed first.
        if (msTemplateSettingExists(msTemplateSettings, selectedTemplateSettingOID) != null) {
            addErrorMessage("MSAE_ERROR_TEMPLATE_ALREADY_ADDED");
            return;
        }

        if (selectedTemplateSettingOID.equals(SELECT_MST)) {
            addErrorMessage("MSAE_ERROR_TEMPLATE");
            return;
        }

        if (selectedCertificationProfileId == null || selectedCertificationProfileId == -1) {
            addErrorMessage("MSAE_ERROR_CEP");
            return;
        }

        if (selectedEndEntityProfile == null || selectedEndEntityProfile.equals(SELECT_EEP)) {
            addErrorMessage("MSAE_ERROR_EEP");
            return;
        }

        selectedCertificationProfile = certificateProfileSession.getCertificateProfileName(selectedCertificationProfileId);
        if (selectedCertificationProfile == null) {
            addErrorMessage("MSAE_ERROR_CEP_NAME");
            return;
        }

        addMsTemplateSetting(selectedTemplateSettingOID, selectedEndEntityProfile, selectedCertificationProfile);
    }

    public void addMsTemplateSetting(final String templateOid, final String certProfile, final String eep) {
        List<MSAutoEnrollmentOIDInfo> adTemplates = getAvailableTemplateSettingsFromAD();
        MSAutoEnrollmentOIDInfo template = msTemplateSettingExists(adTemplates, templateOid);

        if (template != null) {
            template.setCertificationProfile(certProfile);
            template.setEndEntityProfile(eep);
            msTemplateSettings.add(template);
            msTemplateSettingsModel = new ListDataModel<>(getMsTemplateSettings());
        } else {
            addErrorMessage("MSAE_TEMPLATE_NOT_FOUND");
        }
    }

    private MSAutoEnrollmentOIDInfo msTemplateSettingExists(List<MSAutoEnrollmentOIDInfo> templates, final String templatedOid) {
        for (MSAutoEnrollmentOIDInfo template: templates) {
            if (template.getOid().equals(templatedOid)) {
                return template;
            }
        }

        return null;
    }

    /**
     * Return available MS Template Settings from Active Directory.
     *
     * @return
     */
    public List<MSAutoEnrollmentOIDInfo> getAvailableTemplateSettingsFromAD() {
        // TODO: Implement
        List<MSAutoEnrollmentOIDInfo> templates = new ArrayList<>();

        MSAutoEnrollmentOIDInfo oid1 = new MSAutoEnrollmentOIDInfo();
        oid1.setOid("Template 1");
        templates.add(oid1);

        MSAutoEnrollmentOIDInfo oid2 = new MSAutoEnrollmentOIDInfo();
        oid2.setOid("Template 2");
        templates.add(oid2);

        MSAutoEnrollmentOIDInfo oid3 = new MSAutoEnrollmentOIDInfo();
        oid3.setOid("Template 3");
        templates.add(oid3);

        return templates;
    }

    public List<SelectItem> getAvailableTemplateSettingOIDs() {
        availableTemplateSettingOIDs = new ArrayList<>();
        availableTemplateSettingOIDs.add(new SelectItem(SELECT_MST));

        for (MSAutoEnrollmentOIDInfo template: getAvailableTemplateSettingsFromAD()) {
            availableTemplateSettingOIDs.add(new SelectItem(template.getOid()));
        }

        return availableTemplateSettingOIDs;
    }

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

    public List<SelectItem> getAvailableCertificationProfiles() {
        availableCertificationProfiles = new ArrayList<>();
        availableCertificationProfiles.add(new SelectItem(-1, SELECT_CEP));

        for (final Map.Entry<String,Integer> entry : getAllCertificateProfiles().entrySet()) {
            final int certProfileId = entry.getValue(); // map is inverted
            final String certProfileName = entry.getKey();
            availableCertificationProfiles.add(new SelectItem(certProfileId, certProfileName));
        }

        return availableCertificationProfiles;
    }

    public List<SelectItem> getAvailableEndEntityProfiles() {
        availableEndEntityProfiles = new ArrayList<>();
        availableEndEntityProfiles.add(new SelectItem(SELECT_EEP));

        if (selectedCertificationProfileId != null){
            List<String> eepNames = endEntityProfileSession.getEndEntityProfilesUsingCertificateProfile(selectedCertificationProfileId);
            for (String eepName: eepNames) {
                availableEndEntityProfiles.add(new SelectItem(eepName));
            }
        }

        return availableEndEntityProfiles;
    }

    public String getSelectedTemplateSettingOID() {
        return selectedTemplateSettingOID;
    }

    public void setSelectedTemplateSettingOID(String selectedTemplateSettingOID) {
        this.selectedTemplateSettingOID = selectedTemplateSettingOID;
    }

    public String getSelectedCertificationProfile() {
        return selectedCertificationProfile;
    }

    public void setSelectedCertificationProfile(String selectedCertificationProfile) {
        this.selectedCertificationProfile = selectedCertificationProfile;
    }

    public Integer getSelectedCertificationProfileId() {
        return selectedCertificationProfileId;
    }

    public void setSelectedCertificationProfileId(Integer selectedCertificationProfileId) {
        this.selectedCertificationProfileId = selectedCertificationProfileId;
    }

    public String getSelectedEndEntityProfile() {
        return selectedEndEntityProfile;
    }

    public void setSelectedEndEntityProfile(String selectedEndEntityProfile) {
        this.selectedEndEntityProfile = selectedEndEntityProfile;
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
            autoEnrollmentConfiguration.setMsTemplateSettings(msTemplateSettings);

            globalConfigurationSession.saveConfiguration(getAdmin(), autoEnrollmentConfiguration);
            addInfoMessage("CONFIGURATION_AUTOENROLLMENT_SAVE_OK");

        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the MS Auto Enrollment because the current "
                              + "administrator is not authorized. Error description: " + e.getMessage());
            // TODO: Error message
            addErrorMessage("CONFIGURATION_AUTOENROLLMENT_SAVE_ERROR");
        }
    }
}
