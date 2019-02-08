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

package org.ejbca.issuetracker.ui;

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
import org.ejbca.config.IssueTrackerConfiguration;
import org.ejbca.issuetracker.IssueSet;
import org.ejbca.issuetracker.ejb.IssueTrackerSessionBeanLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the 'Issue Tracker' tab in the System Configuration.
 *
 * @version $Id: $
 */
@ManagedBean(name = "issueTrackerSettings")
@ViewScoped
public class IssueTrackerSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(IssueTrackerManagedBean.class);
    private static final long serialVersionUID = 1L;
    private boolean isIssueTrackerEnabled;
    private List<IssueSetStatus> allIssueSetsAndTheirStatus;

    @EJB
    private IssueTrackerSessionBeanLocal issueTrackerSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {
        final IssueTrackerConfiguration issueTrackerConfiguration = (IssueTrackerConfiguration)
                globalConfigurationSession.getCachedConfiguration(IssueTrackerConfiguration.CONFIGURATION_ID);
        final Set<String> enabledIssueSets = issueTrackerConfiguration.getEnabledIssueSets();
        allIssueSetsAndTheirStatus = issueTrackerSession.getAllIssueSets()
                .stream()
                .map(issueSet -> new IssueSetStatus(issueSet, enabledIssueSets.contains(issueSet.getDatabaseValue())))
                .collect(Collectors.toList());
        isIssueTrackerEnabled = issueTrackerConfiguration.isIssueTrackerEnabled();
    }

    public List<IssueSetStatus> getAllIssueSetsAndTheirStatus() {
        return allIssueSetsAndTheirStatus;
    }

    public boolean isIssueTrackerEnabled() {
        return isIssueTrackerEnabled;
    }

    public void setIssueTrackerEnabled(final boolean isIssueTrackerEnabled) {
        this.isIssueTrackerEnabled = isIssueTrackerEnabled;
    }

    public String getLabel(final IssueSet issueSet) {
        final String issueSetTitle = getEjbcaWebBean().getText(issueSet.getTitleLanguageString());
        return getEjbcaWebBean().getText("ISSUE_SET_LABEL", false /* unescape */, issueSetTitle, issueSet.size());
    }

    public String getDescription(final IssueSet issueSet) {
        return getEjbcaWebBean().getText(issueSet.getDescriptionLanguageString());
    }

    public void save() {
        try {
            final IssueTrackerConfiguration issueTrackerConfiguration = (IssueTrackerConfiguration) globalConfigurationSession
                    .getCachedConfiguration(IssueTrackerConfiguration.CONFIGURATION_ID);
            final Set<String> enabledIssueSets = allIssueSetsAndTheirStatus
                    .stream()
                    .filter(issueSetStatus -> issueSetStatus.isEnabled()).map(issueSetStatus -> issueSetStatus.getIssueSet().getDatabaseValue())
                    .collect(Collectors.toSet());
            issueTrackerConfiguration.isIssueTrackerEnabled(isIssueTrackerEnabled);
            issueTrackerConfiguration.setEnabledIssueSets(enabledIssueSets);
            globalConfigurationSession.saveConfiguration(getAdmin(), issueTrackerConfiguration);
            addInfoMessage("ISSUE_TRACKER_SAVE_OK");
        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the EJBCA Issue Tracker because the current "
                    + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("ISSUE_TRACKER_CANNOT_SAVE");
        }
    }
}
