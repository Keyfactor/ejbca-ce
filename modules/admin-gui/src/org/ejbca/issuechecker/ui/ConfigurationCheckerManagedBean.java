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

package org.ejbca.issuechecker.ui;

import java.util.List;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Level;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.ConfigurationCheckerConfiguration;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.db.TicketRequest;
import org.ejbca.issuechecker.ejb.ConfigurationCheckerSessionBean;
import org.ejbca.issuechecker.ejb.ConfigurationCheckerSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the Configuration checker displayed on the front screen. Some business logic is
 * dispatched to {@link ConfigurationCheckerSessionBean}.
 *
 */
@ManagedBean(name = "configurationChecker")
@SessionScoped
public class ConfigurationCheckerManagedBean extends BaseManagedBean {
    private static final long serialVersionUID = 1L;
    private static final int MAX_NUMBER_OF_TICKETS_TO_DISPLAY = 8;

    @EJB
    private ConfigurationCheckerSessionLocal configurationCheckerSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    public String getDescription(final Ticket ticket) {
        return ticket.getTicketDescription().toString(getEjbcaWebBean().getWebLanguages());
    }

    public String getStyleClass(final Ticket ticket) {
        if (ticket.getLevel().isGreaterOrEqual(Level.ERROR)) {
            return "prio-error";
        }
        if (ticket.getLevel().isGreaterOrEqual(Level.WARN)) {
            return "prio-warn";
        } else {
            return "prio-info";
        }
    }

    public List<Ticket> getTickets() {
        return configurationCheckerSession.getTickets(TicketRequest.builder(getAdmin())
                .withLimit(MAX_NUMBER_OF_TICKETS_TO_DISPLAY)
                .build())
            .collect(Collectors.toList());
    }

    public boolean isConfigurationCheckerEnabled() {
        final ConfigurationCheckerConfiguration configurationCheckerConfiguration = (ConfigurationCheckerConfiguration) globalConfigurationSession
                .getCachedConfiguration(ConfigurationCheckerConfiguration.CONFIGURATION_ID);
        return configurationCheckerConfiguration.isConfigurationCheckerEnabled();
    }

    public String getConfigurationIssueHelpReference(final Ticket ticket) {
        if (!getEjbcaWebBean().isHelpEnabled()) {
            return "#";
        }
        return getEjbcaWebBean().getHelpBaseURI() + "/Configuration_Issues.html#" + ticket.getIssue().getDatabaseValue();
    }
}

