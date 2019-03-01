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

package org.ejbca.issuechecker;

import java.util.Set;

/**
 * An issue set groups issues that belong together. Each issue set contains a set of issues,
 * a title and a description. Issue sets can be enabled and disabled in the system configuration.
 *
 * <p>Each issue set can contain any number of issues, and an issue may reside in more than one
 * issue set.
 *
 * <p>An example of an issue set could be "Certificate Transparency" enabled by CAs publishing
 * to CT logs, or the issue set "CA/B Forum Baseline Requirements" enabled by CAs adhering to the
 * Baseline Requirements.
 *
 * @version $Id$
 */
public abstract class ConfigurationIssueSet {

    /**
     * Get the set of classes representing the issues contained in this issue set.
     *
     * @return the classes for the issues contained in this issue set.
     */
    public abstract Set<Class<? extends ConfigurationIssue>> getConfigurationIssues();

    /**
     * Get the title of this issue set, as a language key. The title should be a short
     * text, typically less than 5 words, describing the issues contained in this issue
     * set, e.g. "Certificate Transparency" or "CA/B Forum Baseline Requirements".
     *
     * @return the title of this issue set, as a language string.
     */
    public abstract String getTitleLanguageString();

    /**
     * Get the description of this issue set, as a language key. The description should be a
     * fairly short text, typically less than 20 words, describing the issues contained in this
     * issue set.
     *
     * @return the description of this issue set, as a language string.
     */
    public abstract String getDescriptionLanguageString();

    /**
     * Get the string representing this class in persistent storage. The return value is typically, but
     * does not have to be, the name of the implementing class.
     *
     * <p><b>Implementation note:</b> The value returned by this function must be unique and is <u>not
     * allowed to change</u> for compatibility reasons.
     *
     * @return the string representing this class in persistent storage.
     */
    public abstract String getDatabaseValue();

    /**
     * Returns the number of issues contained in this issue set.
     *
     * @return the number of issues.
     */
    public int size() {
        return getConfigurationIssues().size();
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null) {
            return false;
        }
        return this.getClass() == o.getClass();
    }

    @Override
    public int hashCode() {
        return this.getClass().hashCode();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
    }
}
