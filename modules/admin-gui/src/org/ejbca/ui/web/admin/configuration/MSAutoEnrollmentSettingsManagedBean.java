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

    // MSAE Settings
    private boolean isUseSSL;

    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {

        final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

        // Get values
        if (autoEnrollmentConfiguration != null) {
            isUseSSL = autoEnrollmentConfiguration.isUseSSL();
        }
    }

    public boolean isUseSSL() {
        return isUseSSL;
    }

    public void setUseSSL(final boolean isUseSSL) {
        this.isUseSSL = isUseSSL;
    }

    public void save() {
        try {
            final MSAutoEnrollmentConfiguration autoEnrollmentConfiguration = (MSAutoEnrollmentConfiguration)
                    globalConfigurationSession.getCachedConfiguration(MSAutoEnrollmentConfiguration.CONFIGURATION_ID);

            autoEnrollmentConfiguration.setIsUseSsl(isUseSSL);

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
