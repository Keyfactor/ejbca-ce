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
 * Represents a request for tickets.
 *
 * @version $Id$
 */
public class TicketRequest {
    private final AuthenticationToken authenticationToken;
    private final int limit;
    private final int offset;
    private final Level minimumLevel;

    /**
     * Get a builder for constructing instances of this class.
     *
     * @param authenticationToken the authentication token to be used for the request.
     * @return a builder for this class.
     */
    public static TicketRequestBuilder builder(final AuthenticationToken authenticationToken) {
        return new TicketRequestBuilder(authenticationToken);
    }

    /**
     * Construct a new request for tickets.
     *
     * @param builder a builder of {@link TicketRequest} objects.
     */
    protected TicketRequest(final TicketRequestBuilder builder) {
        this.authenticationToken = builder.authenticationToken;
        this.limit = builder.limit;
        this.offset = builder.offset;
        this.minimumLevel = builder.minimumLevel;
    }

    /**
     * Get an authentication token to be used for access control.
     *
     * @return an authentication token for this request.
     */
    public AuthenticationToken getAuthenticationToken() {
        return authenticationToken;
    }

    /**
     * Get an integer indicating the maximum amount of tickets to be requested.
     *
     * @return the maximum amount of tickets to be returned in the response.
     */
    public int getLimit() {
        return limit;
    }

    /**
     * Get an integer indicating the number of tickets to skip.
     *
     * @return the number of tickets to skip in this request.
     */
    public int getOffset() {
        return offset;
    }

    /**
     * Get the minimum level for tickets. Tickets with a lower level than what is indicated by this function
     * shall not be present in the response.
     *
     * @return the minimum level for tickets in the response.
     */
    public Level getMinimumLevel() {
        return minimumLevel;
    }
}
