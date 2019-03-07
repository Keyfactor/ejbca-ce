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

package org.ejbca.issuechecker.mock.issueset;

import java.util.Set;

import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.mock.issues.BlackIssue;

import com.google.common.collect.ImmutableSet;

/**
 * A configuration issue set used as a mock in unit testing.
 * 
 * <p>Contains a single {@link BlackIssue}.
 * 
 * @version $Id$
 */
public class BlackIssueSet extends RedIssueSet {

    @Override
    public Set<Class<? extends ConfigurationIssue>> getConfigurationIssues() {
        return ImmutableSet.of(BlackIssue.class);
    }

    @Override
    public String getTitleLanguageString() {
        return "BLACK_ISSUE_SET_TITLE";
    }

    @Override
    public String getDescriptionLanguageString() {
        return "BLACK_ISSUE_SET_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "BlackIssueSet";
    }
}
