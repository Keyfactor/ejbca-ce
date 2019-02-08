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

import java.util.Optional;

import org.apache.log4j.Priority;

/**
 * A ticket is the <i>realisation of an issue</i>. A ticket has a priority, a description
 * and optionally a target. An issue may only produce one ticket, in which case the ticket
 * may have a target, or multiple tickets, in which case each individual ticket must have
 * a unique target.
 *
 * <p>For example, one issue could be a specific misconfiguration in a certificate profile.
 * The issue would then produce one ticket per misconfigured certificate profile, where the
 * certificate profile is the target of the ticket.
 *
 * <p>Tickets can be displayed in the GUI, logged to disk, propagated to a separate
 * log management solution or exposed through an API for monitoring purposes.
 *
 * @version $Id$
 */
public class Ticket implements Comparable<Ticket> {
    private final Issue issue;
    private final String descriptionLanguageKey;
    private final String target;

    /**
     * Construct a ticket without a target.
     *
     * @param issue the issue which caused this ticket.
     * @param descriptionLanguageKey the description of this ticket, as a language key.
     */
    public Ticket(final Issue issue, final String descriptionLanguageKey) {
        this(issue, descriptionLanguageKey, null);
    }

    /**
     * Construct a ticket with a target.
     *
     * @param issue the issue which caused this ticket.
     * @param descriptionLanguageKey the description of this ticket, as a language key.
     * @param target the target of this ticket, as a string.
     */
    public Ticket(final Issue issue, final String descriptionLanguageKey, final String cause) {
        this.issue = issue;
        this.descriptionLanguageKey = descriptionLanguageKey;
        this.target = cause;
    }

    /**
     * Get the issue which caused this ticket.
     *
     * @return the issue which caused this ticket.
     */
    public Issue getIssue() {
        return issue;
    }

    /**
     * Get the description of this ticket, as a language key. The description should be a short text
     * (typically around 20 words), describing what the problem is and how the ticket can be resolved,
     * or if the ticket is informative only, what the ticket is about. E.g. "EJBCA is not running in
     * production mode, system tests may run on this instance and additional tools for developers are
     * available."
     *
     * @return the description of this ticket, as a language key.
     */
    public String getDescriptionLanguageKey() {
        return descriptionLanguageKey;
    }

    /**
     * Get an optional containing the cause of this ticket as a string, if this ticket has a cause,
     * or an empty optional if this ticket has no cause.
     *
     * @return the cause of this ticket as a string, if any.
     */
    public Optional<String> getTarget() {
        return Optional.ofNullable(target);
    }

    /**
     * Get the priority of this ticket. The default implementation inherits the priority of the issue
     * e.g. it returns <code>Ticket.getIssue().getPriority()</code>.
     *
     * @return the Log4j priority of this ticket.
     */
    public Priority getPriority() {
        return issue.getPriority();
    }

    /**
     * Compare this object for equality against another object.
     * <p>This object is considered equal to the object given as argument iff the following is true:
     * <ul>
     *     <li>The object given as argument is an instance of {@link #Ticket}.</li>
     *     <li>This issue of this ticket is equal to the issue of the ticket given as argument.</li>
     *     <li>The target of this ticket is equal to the target of the ticket given as argument.</li>
     * </ul>
     *
     * @param o the object to compare for equality.
     * @return true if this ticket is equal to the object given as argument.
     */
    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (null == o) {
            return false;
        }
        if (!(o instanceof Ticket)) {
            return false;
        }
        final Ticket ticket = (Ticket) o;
        return this.getIssue().equals(ticket.getIssue()) &&
                this.getTarget().equals(Optional.ofNullable(ticket.getTarget()));
    }

    /**
     * Compare this ticket to another ticket in ascending order based on priority.
     */
    @Override
    public int compareTo(final Ticket ticket) {
        return ticket.getPriority().toInt() - this.getPriority().toInt();
    }
}
