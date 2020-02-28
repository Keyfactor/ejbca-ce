/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

/**
 * Checks that, if e-mail notifications are enabled in either Approval Profiles or End Entity Profiles, then e-mail is also configured in the appserver.
 * 
 * @version $Id$
 */
public class MissingEmailConfiguration extends ConfigurationIssue {
    
    private static final Logger log = Logger.getLogger(MissingEmailConfiguration.class);

    private static final String APPROVALPROFILE_LANGUAGE_KEY = "MISSING_EMAIL_CONFIGURATION_APPROVALPROFILE_TICKET_DESCRIPTION";
    private static final String ENDENTITYPROFILE_LANGUAGE_KEY = "MISSING_EMAIL_CONFIGURATION_ENDENTITYPROFILE_TICKET_DESCRIPTION";

    private final ApprovalProfileSession approvalProfileSession;
    private final EndEntityProfileSession endEntityProfileSession;
    private final Supplier<Boolean> isEmailConfigured;

    public MissingEmailConfiguration(final ApprovalProfileSession approvalProfileSession, final EndEntityProfileSession endEntityProfileSession,
            final Supplier<Boolean> isEmailConfigured) {
        this.approvalProfileSession = approvalProfileSession;
        this.endEntityProfileSession = endEntityProfileSession;
        this.isEmailConfigured = isEmailConfigured;
    }

    @Override
    public Level getLevel() {
        return Level.ERROR;
    }
    
    @Override
    public String getDescriptionLanguageKey() {
        return "MISSING_EMAIL_CONFIGURATION_ISSUE_DESCRIPTION";
    }
    
    @Override
    public String getDatabaseValue() {
        return "MissingEmailConfiguration";
    }

    @Override
    public List<Ticket> getTickets() {
        final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken("Configuration Checker");
        final List<Ticket> tickets = new ArrayList<>();
        boolean checkedEmailConfiguration = false;
        // Check Approval Profiles
        for (int profileId : approvalProfileSession.getAuthorizedApprovalProfileIds(admin)) {
            final ApprovalProfile profile = approvalProfileSession.getApprovalProfile(profileId);
            log.trace("Checking Approval Profile");
            for (final ApprovalStep step : profile.getStepList()) {
                log.trace("Checking Approval Step");
                for (final ApprovalPartition partition : step.getPartitionList()) {
                    log.trace("Checking Approval Partition");
                    if (!profile.isNotificationEnabled(partition) && !profile.isUserNotificationEnabled(partition)) {
                        continue;
                    }
                    log.trace("Found Approval Profile with notifications enabled");
                    if (!checkedEmailConfiguration) {
                        if (isEmailConfigured.get()) {
                            log.trace("Email is enabled => OK");
                            return Collections.emptyList();
                        }
                        checkedEmailConfiguration = true;
                    }
                    tickets.add(Ticket
                            .builder(this, TicketDescription.fromResource(APPROVALPROFILE_LANGUAGE_KEY, profile.getProfileName()))
                            .withAccessControl(authenticationToken -> approvalProfileSession.isAuthorizedToView(authenticationToken, profileId))
                            .build());
                }
            }
        }
        // Check End Entity Profiles
        final Map<Integer,String> eepIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        for (int profileId : eepIdToNameMap.keySet()) {
            log.trace("Checking End Entity Profile");
            final EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(profileId);
            if (!profile.isSendNotificationUsed()) {
                continue;
            }
            log.trace("Found End Entity Profile with notifications enabled");
            if (!checkedEmailConfiguration) {
                if (isEmailConfigured.get()) {
                    log.trace("Email is enabled => OK");
                    return Collections.emptyList();
                }
                checkedEmailConfiguration = true;
            }
            final String profileName = eepIdToNameMap.get(profileId);
            tickets.add(Ticket
                    .builder(this, TicketDescription.fromResource(ENDENTITYPROFILE_LANGUAGE_KEY, profileName))
                    .withAccessControl(authenticationToken -> endEntityProfileSession.isAuthorizedToView(authenticationToken, profileId))
                    .build());
        }
        return tickets;
    }

}
