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

import org.ejbca.issuechecker.ConfigurationIssueSet;

/**
 * Represents a mutable pair (issueSet, status) rendered in the GUI.
 *
 * @version $Id: IssueSetStatus.java 31452 2019-02-08 18:35:25Z bastianf $
 */
public class ConfigurationStatus {
    private ConfigurationIssueSet issueSet;
    private boolean isEnabled;

    public ConfigurationStatus(final ConfigurationIssueSet issueSet, final boolean isEnabled) {
        this.issueSet = issueSet;
        this.isEnabled = isEnabled;
    }

    public boolean isEnabled() {
        return isEnabled;
    }

    public void setEnabled(final boolean isEnabled) {
        this.isEnabled = isEnabled;
    }

    public ConfigurationIssueSet getIssueSet() {
        return issueSet;
    }
}
