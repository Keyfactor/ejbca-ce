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

package org.ejbca.issuechecker.issues;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.apache.log4j.Level;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

/**
 * A black configuration issue used as a mock in unit testing. Creates a single ticket with priority 
 * <code>Level.ERROR<code> denying all authentication tokens.
 * 
 * @version $Id$
 */
public class BlackIssue extends RedIssue {

    /**
     * Create a new green configuration issue for unit testing.
     * 
     * @param ticketCount the number of tickets to return when {@link #getTickets()} is invoked.
     * @param level the level of this issue.
     */
    public BlackIssue() {
        super(1, Level.WARN);
    }

    @Override
    public List<Ticket> getTickets() {
        return IntStream.rangeClosed(1, 1)
                .boxed()
                .map(i -> Ticket.builder(this, TicketDescription.fromStringLiteral("Black Ticket " + i))
                        .withAccessControl(authenticationToken -> false)
                        .build())
                .collect(Collectors.toList());
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "BLACK_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "BlackIssue";
    }
}
