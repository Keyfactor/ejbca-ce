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

package org.ejbca.issuechecker.ejb;

import java.util.Set;
import java.util.stream.Stream;

import javax.ejb.Local;

import org.ejbca.issuechecker.IssueSet;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.db.TicketRequest;

/**
 * Methods for the issue checker available locally.
 *
 * @version $Id$
 */
@Local
public interface IssueCheckerSessionBeanLocal {

    /**
     * Get a stream of tickets present on the system, matching the {@link TicketRequest} given as
     * argument.
     *
     * <p>The stream is always filtered based on the issue sets enabled in the system configuration,
     * and is sorted based on level, with the most urgent issues first.
     *
     * @param request a request for tickets.
     * @return a filtered and sorted stream of tickets.
     */
    Stream<Ticket> getTickets(final TicketRequest request);

    /**
     * Get a set of all implemented issue sets.
     *
     * @return a set of all implemented issue sets.
     */
    Set<IssueSet> getAllIssueSets();
}
