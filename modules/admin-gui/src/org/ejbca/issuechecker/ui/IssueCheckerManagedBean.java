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
import org.ejbca.config.IssueCheckerConfiguration;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.db.TicketRequest;
import org.ejbca.issuechecker.ejb.IssueCheckerSessionBean;
import org.ejbca.issuechecker.ejb.IssueCheckerSessionBeanLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * Backing bean for the issue checker displayed on the front screen. Some business logic is
 * dispatched to {@link IssueCheckerSessionBean}.
 *
 * @version $Id: IssueTrackerManagedBean.java 31453 2019-02-10 11:20:44Z bastianf $
 */
@ManagedBean(name = "issueChecker")
@SessionScoped
public class IssueCheckerManagedBean extends BaseManagedBean {
    private static final long serialVersionUID = 1L;
    private static final int MAX_NUMBER_OF_TICKETS_TO_DISPLAY = 8;

    @EJB
    private IssueCheckerSessionBeanLocal issueCheckerSession;
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
        if (ticket.getLevel().isGreaterOrEqual(Level.ERROR)) {
            return "prio-error";
        }
        if (ticket.getLevel().isGreaterOrEqual(Level.WARN)) {
            return "prio-warn";
        }
        return "prio-info";
    }

    public List<Ticket> getTickets() {
        return issueCheckerSession.getTickets(TicketRequest.builder(getAdmin())
                .withLimit(MAX_NUMBER_OF_TICKETS_TO_DISPLAY)
                .build())
            .collect(Collectors.toList());
    }

    public boolean isIssueCheckerEnabled() {
        final IssueCheckerConfiguration issueCheckerConfiguration = (IssueCheckerConfiguration) globalConfigurationSession
                .getCachedConfiguration(IssueCheckerConfiguration.CONFIGURATION_ID);
        return issueCheckerConfiguration.isIssueCheckerEnabled();
    }

    public String getIssueHelpReference(final Ticket ticket) {
        if (!getEjbcaWebBean().isHelpEnabled()) {
            return "#";
        }
        return getEjbcaWebBean().getHelpBaseURI() + "/Issues.html#" + ticket.getIssue().getDatabaseValue();
    }
}

