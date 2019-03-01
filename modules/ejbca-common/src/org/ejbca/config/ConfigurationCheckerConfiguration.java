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
 * Configuration for the EJBCA Configuration Checker.
 *
 * @version $Id$
 */
public class ConfigurationCheckerConfiguration extends ConfigurationBase {
    private static final long serialVersionUID = 1L;
    public static final String CONFIGURATION_ID = "ISSUE_TRACKER";

    private static final String IS_CONFIGURATION_CHECKER_ENABLED = "isIssueCheckerEnabled";
    private static final String ENABLED_ISSUE_SETS = "enabledIssueSets";

    /**
     * Create a new Configuration Checker configuration with the default settings.
     */
    public ConfigurationCheckerConfiguration() {
        data.put(IS_CONFIGURATION_CHECKER_ENABLED, false);
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
     * Retrieve a boolean indicating whether the EJBCA Configuration Checker is enabled or not.
     * If the Configuration Checker is disabled, no issues are checked and the Configuration Checker is
     * invisible in the GUI.
     *
     * @return true if the Configuration Checker is enabled, false otherwise.
     */
    public boolean isConfigurationCheckerEnabled() {
        return Boolean.TRUE.equals(data.get(IS_CONFIGURATION_CHECKER_ENABLED));
    }

    /**
     * Set a boolean indicating whether the EJBCA Configuration Checker should be enabled or not.
     * If the Configuration Checker is disabled, no issues will be checked and the Configuration Checker
     * will be invisible in the GUI.
     *
     * @param isIssueCheckerEnabled a boolean indicating whether the Configuration Checker should be enabled or not.
     */
    public void setConfigurationCheckerEnabled(final boolean isIssueCheckerEnabled) {
        data.put(IS_CONFIGURATION_CHECKER_ENABLED, Boolean.valueOf(isIssueCheckerEnabled));
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
    public void setEnabledConfigurationIssueSets(final Set<String> enabledIssueSets) {
        data.put(ENABLED_ISSUE_SETS, enabledIssueSets);
    }
}
