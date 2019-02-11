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
import org.ejbca.config.IssueCheckerConfiguration;
import org.ejbca.issuechecker.Issue;
import org.ejbca.issuechecker.IssueSet;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.issues.EccWithKeyEncipherment;
import org.ejbca.issuechecker.issues.NotInProductionMode;
import org.ejbca.issuechecker.issuesets.CertificateTransparencyIssueSet;
import org.ejbca.issuechecker.issuesets.EjbcaCommonIssueSet;

import com.google.common.collect.ImmutableSet;

/**
 * Session bean implementing business logic for the EJBCA issue checker.
 *
 * <p>Responsible for instantiating issues and issue sets. It is also able to check for
 * and filter issues as well as creating tickets.
 *
 * @version $Id$
 */
@Singleton
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class IssueCheckerSessionBean implements IssueCheckerSessionBeanLocal, IssueCheckerSessionBeanRemote {
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    /**
     * A set of all implemented issue sets. If you create a new issue set, add it to this set.
     */
    private Set<IssueSet> issueSets;

    /**
     * A set of all implemented issues. If you create a new issue, add it to this set.
     */
    private Set<Issue> issues;

    @PostConstruct
    public void instansiateIssuesAndIssueSets() {
        issues = new ImmutableSet.Builder<Issue>()
                .add(new NotInProductionMode())
                .add(new EccWithKeyEncipherment(certificateProfileSession))
                .build();
        issueSets = new ImmutableSet.Builder<IssueSet>()
                .add(new EjbcaCommonIssueSet())
                .add(new CertificateTransparencyIssueSet())
                .build();
    }

    @Override
    public Stream<Ticket> getTickets() {
        // TODO This is lazily evaluated but perhaps cache the result for performance?
        return issues.stream()
                .filter(issue -> isChecking(issue))
                .map(issue -> issue.getTickets())
                .flatMap(tickets -> tickets.stream())
                .sorted();
    }

    @Override
    public Set<Issue> getAllIssues() {
        return issues;
    }

    @Override
    public Set<IssueSet> getAllIssueSets() {
        return issueSets;
    }

    /**
     * Check whether the issue set given as parameter is enabled or not.
     *
     * @param issueSet the issue set to check.
     * @return true if the issue set is enabled, false otherwise.
     */
    private boolean isIssueSetEnabled(final IssueSet issueSet) {
        final IssueCheckerConfiguration issueTrackerConfiguration = (IssueCheckerConfiguration)
                globalConfigurationSession.getCachedConfiguration(IssueCheckerConfiguration.CONFIGURATION_ID);
        return issueTrackerConfiguration.getEnabledIssueSets().contains(issueSet.getDatabaseValue());
    }

    /**
     * Determine if an issue is being checked or not by looking at whether
     * the issue resides in any of the enabled issue sets.
     *
     * @param issue the issue to look for in one of the issue sets
     * @return true if the issue is being tracked, false otherwise
     */
    private boolean isChecking(final Issue issue) {
        return issueSets.stream()
                .filter(issueSet -> isIssueSetEnabled(issueSet))
                .anyMatch(issueSet -> issueSet.getIssues().contains(issue.getClass()));
    }
}
