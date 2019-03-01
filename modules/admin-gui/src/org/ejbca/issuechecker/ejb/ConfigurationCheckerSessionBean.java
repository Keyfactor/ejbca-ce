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

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Singleton;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.ejbca.config.ConfigurationCheckerConfiguration;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.ConfigurationIssueSet;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.db.TicketRequest;
import org.ejbca.issuechecker.issues.EccWithKeyEncipherment;
import org.ejbca.issuechecker.issues.NotInProductionMode;
import org.ejbca.issuechecker.issuesets.CertificateTransparencyConfigurationIssueSet;
import org.ejbca.issuechecker.issuesets.EjbcaCommonIssueSet;

import com.google.common.collect.ImmutableSet;

/**
 * Singleton session bean implementing business logic for the EJBCA Configuration Checker.
 *
 * <p>This session bean is responsible for instantiating configuration issues and configuration issue sets. It is also able
 * to check for configuration issues and create the appropriate tickets.
 *
 * <p>This session bean is also responsible for enforcing access control on individual tickets as they are
 * requested, i.e. filter out tickets to which a user does not have access.
 *
 * @version $Id$
 */
@Singleton
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ConfigurationCheckerSessionBean implements ConfigurationCheckerSessionLocal, ConfigurationCheckerSessionRemote {
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    /**
     * A set of all implemented issue sets. If you create a new issue set, add it to this set.
     */
    private Set<ConfigurationIssueSet> configurationIssueSets;

    /**
     * A set of all implemented issues. If you create a new issue, add it to this set.
     */
    private Set<ConfigurationIssue> configurationIssues;

    @PostConstruct
    public void instansiateConfigurationIssuesAndConfigurationIssueSets() {
        configurationIssues = new ImmutableSet.Builder<ConfigurationIssue>()
                .add(new NotInProductionMode())
                .add(new EccWithKeyEncipherment(certificateProfileSession))
                .build();
        configurationIssueSets = new ImmutableSet.Builder<ConfigurationIssueSet>()
                .add(new EjbcaCommonIssueSet())
                .add(new CertificateTransparencyConfigurationIssueSet())
                .build();
    }

    @Override
    public Stream<Ticket> getTickets(final TicketRequest request) {
        return configurationIssues.stream()
                .filter(issue -> isChecking(issue))
                .map(issue -> issue.getTickets())
                .flatMap(tickets -> tickets.stream())
                .sorted()
                .filter(ticket -> ticket.isAuthorizedToView(request.getAuthenticationToken()))
                .filter(ticket -> ticket.getLevel().isGreaterOrEqual(request.getMinimumLevel()))
                .skip(request.getOffset())
                .limit(request.getLimit());
    }

    @Override
    public Set<ConfigurationIssueSet> getAllConfigurationIssueSets() {
        return configurationIssueSets;
    }

    /**
     * Check whether the issue set given as parameter is enabled or not.
     *
     * @param configurationIssueSet the issue set to check.
     * @return true if the issue set is enabled, false otherwise.
     */
    private boolean isConfigurationIssueSetEnabled(final ConfigurationIssueSet configurationIssueSet) {
        final ConfigurationCheckerConfiguration configurationCheckerConfiguration = (ConfigurationCheckerConfiguration)
                globalConfigurationSession.getCachedConfiguration(ConfigurationCheckerConfiguration.CONFIGURATION_ID);
        return configurationCheckerConfiguration.getEnabledIssueSets().contains(configurationIssueSet.getDatabaseValue());
    }

    /**
     * Determine if an issue is being checked or not by looking at whether
     * the issue resides in any of the enabled issue sets.
     *
     * @param configurationIssue the issue to look for in one of the issue sets
     * @return true if the issue is being tracked, false otherwise
     */
    private boolean isChecking(final ConfigurationIssue configurationIssue) {
        return configurationIssueSets.stream()
                .filter(configurationIssueSet -> isConfigurationIssueSetEnabled(configurationIssueSet))
                .anyMatch(configurationIssueSet -> configurationIssueSet.getConfigurationIssues().contains(configurationIssue.getClass()));
    }
}
