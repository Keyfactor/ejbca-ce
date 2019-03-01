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

package org.ejbca.issuechecker.ui;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.ConfigurationCheckerConfiguration;
import org.ejbca.issuechecker.ConfigurationIssueSet;
import org.ejbca.issuechecker.ejb.ConfigurationCheckerSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the 'Configuration Checker' tab in the System Configuration.
 *
 * @version $Id: IssueTrackerSettingsManagedBean.java 31452 2019-02-08 18:35:25Z bastianf $
 */
@ManagedBean(name = "configurationCheckerSettings")
@ViewScoped
public class ConfigurationCheckerSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(ConfigurationCheckerManagedBean.class);
    private static final long serialVersionUID = 1L;
    private boolean isConfigurationCheckerEnabled;
    private List<ConfigurationIssueSetStatus> allConfigurationIssueSetsAndTheirStatus;

    @EJB
    private ConfigurationCheckerSessionLocal configurationCheckerSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {
        final ConfigurationCheckerConfiguration issueCheckerConfiguration = (ConfigurationCheckerConfiguration)
        globalConfigurationSession.getCachedConfiguration(ConfigurationCheckerConfiguration.CONFIGURATION_ID);
        final Set<String> enabledIssueSets = issueCheckerConfiguration.getEnabledIssueSets();
        allConfigurationIssueSetsAndTheirStatus = configurationCheckerSession.getAllConfigurationIssueSets()
                .stream()
                .map(issueSet -> new ConfigurationIssueSetStatus(issueSet, enabledIssueSets.contains(issueSet.getDatabaseValue())))
                .collect(Collectors.toList());
        isConfigurationCheckerEnabled = issueCheckerConfiguration.isConfigurationCheckerEnabled();
    }

    public List<ConfigurationIssueSetStatus> getAllConfigurationIssueSetsAndTheirStatus() {
        return allConfigurationIssueSetsAndTheirStatus;
    }

    public boolean isConfigurationCheckerEnabled() {
        return isConfigurationCheckerEnabled;
    }

    public void setConfigurationCheckerEnabled(final boolean isConfigurationCheckerEnabled) {
        this.isConfigurationCheckerEnabled = isConfigurationCheckerEnabled;
    }

    public String getLabel(final ConfigurationIssueSet configurationIssueSet) {
        final String configurationIssueSetTitle = getEjbcaWebBean().getText(configurationIssueSet.getTitleLanguageString());
        return getEjbcaWebBean().getText("CONFIGURATION_ISSUESET_LABEL", false /* unescape */, configurationIssueSetTitle,
                configurationIssueSet.size());
    }

    public String getDescription(final ConfigurationIssueSet configurationIssueSet) {
        return getEjbcaWebBean().getText(configurationIssueSet.getDescriptionLanguageString());
    }

    public void save() {
        try {
            final ConfigurationCheckerConfiguration configurationCheckerConfiguration = (ConfigurationCheckerConfiguration) globalConfigurationSession
                    .getCachedConfiguration(ConfigurationCheckerConfiguration.CONFIGURATION_ID);
            final Set<String> configurationIssueSets = allConfigurationIssueSetsAndTheirStatus
                    .stream()
                    .filter(configurationIssueSetStatus -> configurationIssueSetStatus.isEnabled())
                    .map(configurationIssueSetStatus -> configurationIssueSetStatus.getConfigurationIssueSet().getDatabaseValue())
                    .collect(Collectors.toSet());
            configurationCheckerConfiguration.setConfigurationCheckerEnabled(isConfigurationCheckerEnabled);
            configurationCheckerConfiguration.setEnabledConfigurationIssueSets(configurationIssueSets);
            globalConfigurationSession.saveConfiguration(getAdmin(), configurationCheckerConfiguration);
            addInfoMessage("CONFIGURATION_CHECKER_SAVE_OK");
        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the EJBCA Configuration Checker because the current "
                    + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("CONFIGURATION_CHECKER_CANNOT_SAVE");
        }
    }
}
