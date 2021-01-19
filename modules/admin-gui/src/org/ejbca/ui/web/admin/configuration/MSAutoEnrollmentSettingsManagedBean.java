package org.ejbca.ui.web.admin.configuration;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.MSAutoEnrollmentConfiguration;
import org.ejbca.ui.web.admin.BaseManagedBean;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

/**
 * Backing bean for MSAutoEnrollmentConfiguration in System Settings.
 */
@ManagedBean(name = "msAutoEnrollmentSettings")
@ViewScoped
public class MSAutoEnrollmentSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(MSAutoEnrollmentSettingsManagedBean.class);
    private static final long serialVersionUID = 1L;

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
        }
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
