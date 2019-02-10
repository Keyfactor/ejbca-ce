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

package org.ejbca.issuetracker;

import java.util.List;

import org.apache.log4j.Priority;

/**
 * An issue is a type of problem which can be tracked by the EJBCA issue tracker. Each issue has
 * a priority and a description. An issue can produce one or more tickets if present on the system.
 *
 * @version $Id$
 */
public abstract class Issue {
    /**
     * Get a list of tickets caused by this issue. Returns an empty list of tickets if this issue
     * is not present on the system, or at least one ticket if present.
     *
     * @return a list of zero or more issues caused by this ticket, never null.
     */
    abstract public List<Ticket> getTickets();

    /**
     * Get the Log4j priority of this issue, determining how this issue is displayed and logged.
     *
     * <p>As a rule of thumb, use the priority
     * <ul>
     *     <li><b>Priority.INFO</b> for issues of an informative nature, i.e. issues which do not
     *     necessarily require any action being carried out by administrator. E.g. system information,
     *     statistics and advice for improving the usability, security and performance of the system.</li>
     *     <li><b>Priority.WARNING</b> for issues which requires attention from an administrator,
     *     and should be fixed as soon as possible, e.g. editorial configuration errors, or malfunction
     *     in a part of the system where failover is possible.</li>
     *     <li><b>Priority.ERROR</b> for issues which requires attention from an administrator, and
     *     should be fixed immediately. E.g. serious configuration errors or malfunction in a part
     *     of the system where no failover is possible.
     * </ul>
     *
     * @return the Log4j priority of this issue.
     */
    abstract public Priority getPriority();

    /**
     * Get the description of this issue, as a language key. The description should be a short text
     * (typically around 10 words), describing the cause of the issue, e.g. "Warn when EJBCA is
     * not running in production mode."
     *
     * @return the description of this issue, as a language key.
     */
    abstract public String getDescriptionLanguageKey();

    /**
     * Get the string representing this class in persistent storage. The return value is typically, but
     * does not have to be, the name of the implementing class.
     *
     * <p><b>Implementation note:</b> The value returned by this function must be unique and is <u>not
     * allowed to change</u> for compatibility reasons. The return value of this method is also used
     * as anchor in the Confluence documentation.
     *
     * @return the string representing this class in persistent storage.
     */
    public abstract String getDatabaseValue();

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
