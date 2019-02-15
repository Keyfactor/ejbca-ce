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
    protected final String descriptionLanguageKey;
    protected String target;
    protected Predicate<AuthenticationToken> isAuthorizedToView;

    /**
     * Construct a new builder of {@link Ticket} objects.
     *
     * @param issue the issue to use when building the {@link Ticket} object.
     * @param descriptionLanguageKey the description language key to use when building the {@link Ticket} object.
     */
    public TicketBuilder(final Issue issue, final String descriptionLanguageKey) {
        this.issue = issue;
        this.descriptionLanguageKey = descriptionLanguageKey;
    }

    /**
     * Build the {@link Ticket} object with a target (e.g. a peer connector, profile or alias)
     * whose name will be a part of the ticket description.
     *
     * @param target the target to use when building the {@link Ticket} object.
     * @return this builder
     */
    public TicketBuilder withTarget(final String target) {
        this.target = target;
        return this;
    }

    public TicketBuilder withAccessControl(final Predicate<AuthenticationToken> isAuthorizedToView) {
        this.isAuthorizedToView = isAuthorizedToView;
        return this;
    }

    /**
     * Build the {@link Ticket} object.
     *
     * @return the ticket object.
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
