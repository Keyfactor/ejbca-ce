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

package org.ejbca.issuechecker.mock.ejb;

import java.util.Collections;
import java.util.Set;

import org.cesecore.configuration.GlobalConfigurationSession;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.ConfigurationIssueSet;
import org.ejbca.issuechecker.ejb.ConfigurationCheckerSessionBean;
import org.ejbca.issuechecker.ejb.ConfigurationCheckerSessionLocal;

/**
 * A extended version of {@link ConfigurationCheckerSessionBean} suitable for unit testing.
 * 
 * <p>This class has no dependencies to {@link GlobalConfigurationSession} and can be tested in isolation 
 * without an EJB container.
 * 
 * @version $Id$
 */
public class ConfigurationCheckerSessionBeanPartialMock extends ConfigurationCheckerSessionBean {
    private final Set<ConfigurationIssueSet> enabledConfigurationIssueSets;
    
    public static class Builder {
        private Set<ConfigurationIssueSet> enabledConfigurationIssueSets = Collections.emptySet();
        private Set<ConfigurationIssueSet> allConfigurationIssueSets = Collections.emptySet();
        private Set<ConfigurationIssue> allConfigurationIssues = Collections.emptySet();
        
        public Builder withAvailableConfigurationSets(final Set<ConfigurationIssueSet> allConfigurationIssueSets) {
            this.allConfigurationIssueSets = allConfigurationIssueSets;
            return this;
        }
        
        public Builder withEnabledConfigurationSets(final Set<ConfigurationIssueSet> enabledConfigurationIssueSets) {
            this.enabledConfigurationIssueSets = enabledConfigurationIssueSets;
            return this;
        }
        
        public Builder withAvailableConfigurationIssues(final Set<ConfigurationIssue> allConfigurationIssues) {
            this.allConfigurationIssues = allConfigurationIssues;
            return this;
        }
        
        public ConfigurationCheckerSessionLocal buildLocal() {
            if (allConfigurationIssueSets.isEmpty() && !enabledConfigurationIssueSets.isEmpty()) {
                allConfigurationIssueSets = enabledConfigurationIssueSets;
            }
            return new ConfigurationCheckerSessionBeanPartialMock(this);
        }
    }
    
    private ConfigurationCheckerSessionBeanPartialMock(final Builder builder) {
        this.enabledConfigurationIssueSets = builder.enabledConfigurationIssueSets;
        super.allConfigurationIssues = builder.allConfigurationIssues;
        super.allConfigurationIssueSets = builder.allConfigurationIssueSets;
    }

    @Override
    protected boolean isConfigurationIssueSetEnabled(final ConfigurationIssueSet configurationIssueSet) {
        return enabledConfigurationIssueSets.contains(configurationIssueSet);
    }
}