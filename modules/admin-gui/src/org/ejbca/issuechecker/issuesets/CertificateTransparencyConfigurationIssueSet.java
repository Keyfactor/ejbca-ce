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

package org.ejbca.issuechecker.issuesets;

import java.util.Set;

import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.ConfigurationIssueSet;

import com.google.common.collect.ImmutableSet;

/**
 * Configuration issue set containing configuration issues related to Certificate Transparency.
 *
 * @version $Id$
 */
public class CertificateTransparencyConfigurationIssueSet extends ConfigurationIssueSet {
    private final Set<Class<? extends ConfigurationIssue>> configurationIssues = new ImmutableSet.Builder<Class<? extends ConfigurationIssue>>()
            .build();

    @Override
    public Set<Class<? extends ConfigurationIssue>> getConfigurationIssues() {
        return configurationIssues;
    }

    @Override
    public String getDatabaseValue() {
        return "CertificateTransparencyConfigurationIssueSet";
    }

    @Override
    public String getTitleLanguageString() {
        return "CT_ISSUESET_TITLE";
    }

    @Override
    public String getDescriptionLanguageString() {
        return "CT_ISSUESET_DESCRIPTION";
    }
}
