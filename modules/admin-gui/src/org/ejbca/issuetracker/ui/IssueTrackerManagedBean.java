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

package org.ejbca.issuetracker.ui;

import java.util.List;
import java.util.stream.Collectors;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Priority;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.IssueTrackerConfiguration;
import org.ejbca.issuetracker.Ticket;
import org.ejbca.issuetracker.ejb.IssueTrackerSessionBeanLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the issue tracker displayed on the front screen.
 *
 * @version $Id$
 */
@ManagedBean(name = "issueTracker")
@SessionScoped
public class IssueTrackerManagedBean extends BaseManagedBean {
    private static final long serialVersionUID = 1L;
    private static final int MAX_NUMBER_OF_TICKETS_TO_DISPLAY = 10;

    @EJB
    private IssueTrackerSessionBeanLocal issueTrackerSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    public String getDescription(final Ticket ticket) {
        if (ticket.getTarget().isPresent()) {
            return getEjbcaWebBean().getText(ticket.getDescriptionLanguageKey(), /* unescape */ false, ticket.getTarget().get());
        } else {
            return getEjbcaWebBean().getText(ticket.getDescriptionLanguageKey());
        }
    }

    public String getStyleClass(final Ticket ticket) {
        if (ticket.getPriority().isGreaterOrEqual(Priority.ERROR)) {
            return "prio-error";
        }
        if (ticket.getPriority().isGreaterOrEqual(Priority.WARN)) {
            return "prio-warn";
        }
        return "prio-info";
    }

    public List<Ticket> getTickets() {
        return issueTrackerSession.getTickets()
            .limit(MAX_NUMBER_OF_TICKETS_TO_DISPLAY)
            .collect(Collectors.toList());
    }

    public boolean isIssueTrackerEnabled() {
        final IssueTrackerConfiguration issueTrackerConfiguration = (IssueTrackerConfiguration) globalConfigurationSession
                .getCachedConfiguration(IssueTrackerConfiguration.CONFIGURATION_ID);
        return issueTrackerConfiguration.isIssueTrackerEnabled();
    }

    public String getHelpReference(final Ticket ticket) {
        if (!getEjbcaWebBean().isHelpEnabled()) {
            return "#";
        }
        return getEjbcaWebBean().getHelpBaseURI() + "/Issues.html#" + ticket.getIssue().getDatabaseValue();
    }
}

