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

import java.util.Optional;
import java.util.function.Predicate;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;

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
    private final Predicate<AuthenticationToken> isAuthorizedToView;

    /**
     * Get a builder for constructing instances of this class.
     *
     * @param issue the issue which caused the ticket.
     * @param descriptionLanguageKey the description of the ticket, as a language key.
     * @return a builder for this class.
     */
    public static TicketBuilder builder(final Issue issue, final String descriptionLanguageKey) {
        return new TicketBuilder(issue, descriptionLanguageKey);
    }

    /**
     * Construct a new ticket.
     *
     * @param builder a builder of {@link Ticket} objects.
     */
    protected Ticket(final TicketBuilder builder) {
        this.issue = builder.issue;
        this.descriptionLanguageKey = builder.descriptionLanguageKey;
        this.target = builder.target;
        this.isAuthorizedToView = builder.isAuthorizedToView;
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
     * Get the level of this ticket. The default implementation inherits the level of the issue,
     * i.e. it returns <code>Ticket.getIssue().getLevel()</code>.
     *
     * @return the log level of this ticket.
     */
    public Level getLevel() {
        return issue.getLevel();
    }

    /**
     * Determine if the user with the authentication token given as argument is
     * authorized to view this ticket. This function should be used to perform
     * access control before the ticket is displayed in the GUI.
     *
     * @param authenticationToken the authentication token to use for authentication
     * @return true if the user has view access to this ticket.
     */
    public boolean isAuthorizedToView(final AuthenticationToken authenticationToken) {
        return isAuthorizedToView.test(authenticationToken);
    }

    /**
     * Compare this object for equality against another object.
     *
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
                this.getTarget().equals(ticket.getTarget());
    }

    /**
     * Compare this ticket to another ticket in ascending order based on priority.
     */
    @Override
    public int compareTo(final Ticket ticket) {
        return ticket.getLevel().toInt() - this.getLevel().toInt();
    }
}
