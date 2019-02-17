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

package org.ejbca.issuechecker.db;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * A builder of {@link TicketRequest} objects.
 *
 * @version $Id$
 */
public class TicketRequestBuilder {
    protected final AuthenticationToken authenticationToken;
    protected int limit = Integer.MAX_VALUE;
    protected int offset = 0;
    protected Level minimumLevel = Level.ALL;

    /**
     * Construct a new builder of {@link TicketRequest} objects.
     *
     * @param authenticationToken the authenticationToken to use when building the {@link TicketRequest} object.
     */
    protected TicketRequestBuilder(final AuthenticationToken authenticationToken) {
        this.authenticationToken = authenticationToken;
    }

    /**
     * Build the ticket request with a limit, determining the maximum amount of tickets to
     * be returned in the response. See {@link TicketRequest#getLimit()}.
     *
     * @param limit the limit to use when building the {@link TicketRequest} object.
     * @return this builder.
     */
    public TicketRequestBuilder withLimit(final int limit) {
        this.limit = limit;
        return this;
    }

    /**
     * Build the ticket request with an offset, determining the number of tickets to skip.
     * See {@link TicketRequest#getOffset()}.
     *
     * @param offset the offset to use when building the {@link TicketRequest} object.
     * @return this builder.
     */
    public TicketRequestBuilder withOffset(final int offset) {
        this.offset = offset;
        return this;
    }

    /**
     * Build the ticket with a minimum level for filtering tickets in the response.
     * See {@link TicketRequest#getMinimumLevel()}.
     *
     * @param minimumLevel the minimum level to use when building the {@link TicketRequest} object.
     * @return
     */
    public TicketRequestBuilder filterByLevel(final Level minimumLevel) {
        this.minimumLevel = minimumLevel;
        return this;
    }

    /**
     * Build the {@link TicketRequest} object.
     *
     * @return a new instance of the {@link TicketRequest} class.
     */
    public TicketRequest build() {
        return new TicketRequest(this);
    }
}
