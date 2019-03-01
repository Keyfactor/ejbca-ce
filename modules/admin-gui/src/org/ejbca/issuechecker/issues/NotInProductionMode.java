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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Level;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

/**
 * Warn the user whenever EJBCA is not running in production mode.
 *
 * <p>Tickets created by this issue can be viewed by anyone.
 *
 * @version $Id$
 */
public class NotInProductionMode extends ConfigurationIssue {

    @Override
    public List<Ticket> getTickets() {
        if (!EjbcaConfiguration.getIsInProductionMode()) {
            return Arrays.asList(Ticket.builder(this, TicketDescription.fromResource("NOT_IN_PRODUCTION_MODE_TICKET_DESCRIPTION")).build());
        }
        return Collections.emptyList();
    }

    @Override
    public Level getLevel() {
        return Level.INFO;
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "NOT_IN_PRODUCTION_MODE_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "NotInProductionMode";
    }
}
