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

import java.util.function.Predicate;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * A ticket is the <i>realisation of an issue</i>. Each ticket is associated with an
 * issue, a ticket description, and a piece of access control logic.
 * 
 * <p>Tickets can be compared for equality and compared to each other, based on their
 * priority.
 *
 * <p>Tickets can be displayed in the GUI, logged to disk, propagated to a separate
 * log management solution or exposed through an API for monitoring purposes.
 *
 * @version $Id$
 */
public class Ticket implements Comparable<Ticket> {
    private final ConfigurationIssue issue;
    private final TicketDescription ticketDescription;
    private final Predicate<AuthenticationToken> isAuthorizedToView;

    /**
     * Get a builder for constructing instances of this class.
     *
     * @param issue the issue which caused the ticket.
     * @param descriptionLanguageKey the description of the ticket, as a language key.
     * @return a builder for this class.
     */
    public static TicketBuilder builder(final ConfigurationIssue issue, final TicketDescription ticketDescription) {
        return new TicketBuilder(issue, ticketDescription);
    }

    /**
     * Construct a new ticket.
     *
     * @param builder a builder of {@link Ticket} objects.
     */
    protected Ticket(final TicketBuilder builder) {
        this.issue = builder.issue;
        this.ticketDescription = builder.ticketDescription;
        this.isAuthorizedToView = builder.isAuthorizedToView;
    }

    /**
     * Get the issue which caused this ticket.
     *
     * @return the issue which caused this ticket.
     */
    public ConfigurationIssue getIssue() {
        return issue;
    }

    /**
     * Get the description of this ticket.
     *
     * @return the description of this ticket.
     */
    public TicketDescription getTicketDescription() {
        return ticketDescription;
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
               this.getTicketDescription().equals(ticket.getTicketDescription());
    }

    /**
     * Compare this ticket to another ticket in ascending order based on priority.
     * 
     * @return a negative integer if this ticket has higher priority than the ticket given as 
     * argument, zero if both tickets have the same priority, or a positive integer if this 
     * ticket has a lower priority than the ticket given as argument.
     */
    @Override
    public int compareTo(final Ticket ticket) {
        return ticket.getLevel().toInt() - this.getLevel().toInt();
    }
}
