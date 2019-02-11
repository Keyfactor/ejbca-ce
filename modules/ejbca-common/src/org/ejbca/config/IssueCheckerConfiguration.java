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

package org.ejbca.config;

import java.util.HashSet;
import java.util.Set;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Configuration for the EJBCA issue checker.
 *
 * @version $Id$
 */
public class IssueCheckerConfiguration extends ConfigurationBase {
    private static final long serialVersionUID = 1L;
    public static final String CONFIGURATION_ID = "ISSUE_TRACKER";

    private static final String IS_ISSUE_CHECKER_ENABLED = "isIssueCheckerEnabled";
    private static final String ENABLED_ISSUE_SETS = "enabledIssueSets";

    /**
     * Create a new issue checker configuration with the default settings.
     */
    public IssueCheckerConfiguration() {
        data.put(IS_ISSUE_CHECKER_ENABLED, false);
        data.put(ENABLED_ISSUE_SETS, new HashSet<String>());
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, Float.valueOf(LATEST_VERSION));
        }
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    /**
     * Retrieve a boolean indicating whether the EJBCA issue checker is enabled or not.
     * If the issue checker is disabled, no issues are checked and the issue checker is
     * invisible in the GUI.
     *
     * @return true if the issue checker is enabled, false otherwise.
     */
    public boolean isIssueCheckerEnabled() {
        return Boolean.TRUE.equals(data.get(IS_ISSUE_CHECKER_ENABLED));
    }

    /**
     * Set a boolean indicating whether the EJBCA issue checker should be enabled or not.
     * If the issue checker is disabled, no issues will be checked and the issue checker
     * will be invisible in the GUI.
     *
     * @param isIssueCheckerEnabled a boolean indicating whether the issue checker should be enabled or not.
     */
    public void setIssueCheckerEnabled(final boolean isIssueCheckerEnabled) {
        data.put(IS_ISSUE_CHECKER_ENABLED, Boolean.valueOf(isIssueCheckerEnabled));
    }

    /**
     * Get the database values for the enabled issue sets.
     *
     * @return a set of database values, representing the enabled issue sets.
     */
    @SuppressWarnings("unchecked")
    public Set<String> getEnabledIssueSets() {
        return (Set<String>) data.get(ENABLED_ISSUE_SETS);
    }

    /**
     * Set the enabled issue sets by providing a set of database values.
     *
     * @param enabledIssueSets a set of database values, indicating which issue sets should be enabled.
     */
    public void setEnabledIssueSets(final Set<String> enabledIssueSets) {
        data.put(ENABLED_ISSUE_SETS, enabledIssueSets);
    }
}
