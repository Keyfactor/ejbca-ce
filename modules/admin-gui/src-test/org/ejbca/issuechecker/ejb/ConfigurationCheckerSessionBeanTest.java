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

import static org.easymock.EasyMock.createNiceMock;
import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.stream.Collectors;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.db.TicketRequest;
import org.ejbca.issuechecker.mock.ejb.ConfigurationCheckerSessionBeanPartialMock;
import org.ejbca.issuechecker.mock.issues.BlackIssue;
import org.ejbca.issuechecker.mock.issues.GreenIssue;
import org.ejbca.issuechecker.mock.issues.RedIssue;
import org.ejbca.issuechecker.mock.issueset.BlackIssueSet;
import org.ejbca.issuechecker.mock.issueset.GreenIssueSet;
import org.ejbca.issuechecker.mock.issueset.RedIssueSet;
import org.junit.Test;

import com.google.common.collect.ImmutableSet;

/**
 * Unit tests for {@link #ConfigurationCheckerSessionBean}.
 * 
 * @version $Id$
 */
public class ConfigurationCheckerSessionBeanTest {

    private AuthenticationToken getAuthenticationToken() {
        final AuthenticationToken authenticationToken = createNiceMock(AuthenticationToken.class);
        return authenticationToken;
    }

    @Test
    public void retrieveOneTicket() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new GreenIssue(1, Level.INFO)))
                .withEnabledConfigurationSets(ImmutableSet.of(new GreenIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                    .builder(getAuthenticationToken())
                    .build())
                .collect(Collectors.toList());
        assertEquals("Somehow additional tickets were added, or a ticket was erronously discarded.", 1, tickets.size());
        assertEquals("Green Ticket 1", tickets.get(0).getTicketDescription().toString());
    }

    @Test
    public void retrieveThreeTickets() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new GreenIssue(2, Level.INFO), new RedIssue(1, Level.WARN)))
                .withEnabledConfigurationSets(ImmutableSet.of(new GreenIssueSet(), new RedIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                    .builder(getAuthenticationToken())
                    .build())
                .collect(Collectors.toList());
        assertEquals("Somehow additional tickets were added, or a ticket was erronously discarded.", 3, tickets.size());
        assertEquals("The tickets were not sorted correctly, high-priority tickets should be first in the list.", "Red Ticket 1",
                tickets.get(0).getTicketDescription().toString());
        assertEquals("Green Ticket 1", tickets.get(1).getTicketDescription().toString());
        assertEquals("Green Ticket 2", tickets.get(2).getTicketDescription().toString());
    }

    @Test
    public void limitAndOffset() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new GreenIssue(2, Level.INFO), new RedIssue(2, Level.WARN)))
                .withEnabledConfigurationSets(ImmutableSet.of(new GreenIssueSet(), new RedIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                    .builder(getAuthenticationToken())
                    .withLimit(2)
                    .withOffset(1)
                    .build())
                .collect(Collectors.toList());
        assertEquals("Ticket limit or offset was not respected.", 2, tickets.size());
        assertEquals("Red Ticket 2", tickets.get(0).getTicketDescription().toString());
        assertEquals("Green Ticket 1", tickets.get(1).getTicketDescription().toString());
    }
    
    @Test
    public void filterByTicketLevel() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new GreenIssue(2, Level.DEBUG), new RedIssue(1, Level.ERROR)))
                .withEnabledConfigurationSets(ImmutableSet.of(new GreenIssueSet(), new RedIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                    .builder(getAuthenticationToken())
                    .filterByLevel(Level.ERROR)
                    .build())
                .collect(Collectors.toList());
        assertEquals(1, tickets.size());
        assertEquals("Red Ticket 1", tickets.get(0).getTicketDescription().toString());
    }
    
    @Test
    public void disabledIssueSets() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new GreenIssue(1, Level.INFO), new RedIssue(1, Level.WARN)))
                .withAvailableConfigurationSets(ImmutableSet.of(new GreenIssueSet(), new RedIssueSet()))
                .withEnabledConfigurationSets(ImmutableSet.of(new GreenIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                .builder(getAuthenticationToken())
                .build())
            .collect(Collectors.toList());
        assertEquals("Issues belonging to disabled issue sets should not produce tickets.", 1, tickets.size());
        assertEquals("The wrong issue set was disabled.", "Green Ticket 1", tickets.get(0).getTicketDescription().toString());
    }
    
    @Test
    public void hideUnauthorizedTickets() {
        final ConfigurationCheckerSessionLocal configurationCheckerSession = new ConfigurationCheckerSessionBeanPartialMock.Builder()
                .withAvailableConfigurationIssues(ImmutableSet.of(new BlackIssue()))
                .withEnabledConfigurationSets(ImmutableSet.of(new BlackIssueSet()))
                .buildLocal();
        final List<Ticket> tickets = configurationCheckerSession.getTickets(TicketRequest
                    .builder(getAuthenticationToken())
                    .build())
                .collect(Collectors.toList());
        assertEquals("Unauthorized tickets should not be displayed.", 0, tickets.size());
    }
}