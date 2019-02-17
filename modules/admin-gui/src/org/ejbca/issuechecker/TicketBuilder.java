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

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Class for building {@link Ticket} objects.
 *
 * @version $Id$
 */
public class TicketBuilder {
    protected final Issue issue;
    protected final TicketDescription ticketDescription;
    protected Predicate<AuthenticationToken> isAuthorizedToView;

    /**
     * Construct a new builder of {@link Ticket} objects.
     *
     * @param issue the issue to use when building the {@link Ticket} object.
     * @param descriptionLanguageKey the description language key to use when building the {@link Ticket} object.
     */
    protected TicketBuilder(final Issue issue, final TicketDescription ticketDescription) {
        this.issue = issue;
        this.ticketDescription = ticketDescription;
    }

    /**
     * Build the ticket with an access control rule, determining whether the ticket will be visible
     * to a user, based on the authentication token presented.
     *
     * @param isAuthorizedToView a predicate returning true iff the user whose authentication token is
     * given as input should be allowed to view the ticket.
     * @return this builder.
     */
    public TicketBuilder withAccessControl(final Predicate<AuthenticationToken> isAuthorizedToView) {
        this.isAuthorizedToView = isAuthorizedToView;
        return this;
    }

    /**
     * Build the {@link Ticket} object.
     *
     * @return a new instance of the {@link Ticket} class.
     */
    public Ticket build() {
        if (isAuthorizedToView == null) {
            // Default behaviour is to always grant view access to the ticket
            // regardless of which authentication token is presented
            isAuthorizedToView = (authenticationToken) -> true;
        }
        return new Ticket(this);
    }
}
