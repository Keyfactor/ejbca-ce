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
import org.ejbca.config.IssueCheckerConfiguration;
import org.ejbca.issuechecker.IssueSet;
import org.ejbca.issuechecker.ejb.IssueCheckerSessionBeanLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the 'Issue Checker' tab in the System Configuration.
 *
 * @version $Id: IssueTrackerSettingsManagedBean.java 31452 2019-02-08 18:35:25Z bastianf $
 */
@ManagedBean(name = "issueCheckerSettings")
@ViewScoped
public class IssueCheckerSettingsManagedBean extends BaseManagedBean {
    private static final Logger log = Logger.getLogger(IssueCheckerManagedBean.class);
    private static final long serialVersionUID = 1L;
    private boolean isIssueCheckerEnabled;
    private List<IssueSetStatus> allIssueSetsAndTheirStatus;

    @EJB
    private IssueCheckerSessionBeanLocal issueCheckerSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void loadConfiguration() {
        final IssueCheckerConfiguration issueCheckerConfiguration = (IssueCheckerConfiguration)
        globalConfigurationSession.getCachedConfiguration(IssueCheckerConfiguration.CONFIGURATION_ID);
        final Set<String> enabledIssueSets = issueCheckerConfiguration.getEnabledIssueSets();
        allIssueSetsAndTheirStatus = issueCheckerSession.getAllIssueSets()
                .stream()
                .map(issueSet -> new IssueSetStatus(issueSet, enabledIssueSets.contains(issueSet.getDatabaseValue())))
                .collect(Collectors.toList());
        isIssueCheckerEnabled = issueCheckerConfiguration.isIssueCheckerEnabled();
    }

    public List<IssueSetStatus> getAllIssueSetsAndTheirStatus() {
        return allIssueSetsAndTheirStatus;
    }

    public boolean isIssueCheckerEnabled() {
        return isIssueCheckerEnabled;
    }

    public void setIssueCheckerEnabled(final boolean isIssueTrackerEnabled) {
        this.isIssueCheckerEnabled = isIssueTrackerEnabled;
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
            final IssueCheckerConfiguration issueCheckerConfiguration = (IssueCheckerConfiguration) globalConfigurationSession
                    .getCachedConfiguration(IssueCheckerConfiguration.CONFIGURATION_ID);
            final Set<String> enabledIssueSets = allIssueSetsAndTheirStatus
                    .stream()
                    .filter(issueSetStatus -> issueSetStatus.isEnabled())
                    .map(issueSetStatus -> issueSetStatus.getIssueSet().getDatabaseValue())
                    .collect(Collectors.toSet());
            issueCheckerConfiguration.setIssueCheckerEnabled(isIssueCheckerEnabled);
            issueCheckerConfiguration.setEnabledIssueSets(enabledIssueSets);
            globalConfigurationSession.saveConfiguration(getAdmin(), issueCheckerConfiguration);
            addInfoMessage("ISSUE_CHECKER_SAVE_OK");
        } catch (AuthorizationDeniedException e) {
            log.error("Cannot save the configuration for the EJBCA Issue Checker because the current "
                    + "administrator is not authorized. Error description: " + e.getMessage());
            addErrorMessage("ISSUE_CHECKER_CANNOT_SAVE");
        }
    }
}
