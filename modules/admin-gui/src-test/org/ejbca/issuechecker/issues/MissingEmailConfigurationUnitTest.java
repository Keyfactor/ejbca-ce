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

import static org.easymock.EasyMock.createStrictMock;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.reset;
import static org.easymock.EasyMock.same;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.MapTools;
import org.cesecore.util.ui.PropertyValidationException;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.approval.ApprovalProfileSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for {@link MissingEmailConfiguration}.
 * 
 * @version $Id$
 */
public class MissingEmailConfigurationUnitTest {
    private static final Logger log = Logger.getLogger(MissingEmailConfigurationUnitTest.class);
    
    private static final int APPROVALPROFILE1_ID = 51;
    private static final int APPROVALPROFILE2_ID = -345;
    private static final String APPROVALPROFILE1_NAME = "Approval Profile One";
    private static final String APPROVALPROFILE2_NAME = "Approval Profile Two";
    private static final List<Integer> APPROVALPROFILE_IDS = Arrays.asList(APPROVALPROFILE1_ID, APPROVALPROFILE2_ID);
    private static final int ENDENTITYPROFILE_ID = 9723;
    private static final String ENDENTITYPROFILE_NAME = "Test End Entity Profile";
    private static PartitionedApprovalProfile approvalProfile1;
    private static AccumulativeApprovalProfile approvalProfile2;
    private static EndEntityProfile endEntityProfile;
    
    private ApprovalProfileSession approvalProfileSession;
    private EndEntityProfileSession endEntityProfileSession;
    private Supplier<Boolean> isEmailConfigured;
    
    @BeforeClass
    public static void beforeClass() throws PropertyValidationException {
        log.trace(">beforeClass");
        approvalProfile1 = new PartitionedApprovalProfile(APPROVALPROFILE1_NAME);
        final ApprovalStep step1 = approvalProfile1.addStepLast();
        final ApprovalPartition partition = step1.addPartition();
        approvalProfile1.addNotificationProperties(partition, "recipient@example", "sender@example", "Dummy subject", "Dummy body");
        approvalProfile2 = new AccumulativeApprovalProfile(APPROVALPROFILE2_NAME);
        approvalProfile2.setNumberOfApprovalsRequired(1);
        endEntityProfile = new EndEntityProfile(true);
        endEntityProfile.setSendNotificationUsed(true);
        log.trace("<beforeClass");
    }
    
    @Before
    public void beforeTest() {
        approvalProfileSession = createStrictMock(ApprovalProfileSession.class);
        endEntityProfileSession = createStrictMock(EndEntityProfileSession.class);
        isEmailConfigured = createStrictMock(Supplier.class);
    }
    
    private void expectSteps(final boolean emailEnabled) {
        expect(approvalProfileSession.getAuthorizedApprovalProfileIds(EasyMock.anyObject())).andReturn(APPROVALPROFILE_IDS);
        expect(approvalProfileSession.getApprovalProfile(APPROVALPROFILE1_ID)).andReturn(approvalProfile1);
        expect(isEmailConfigured.get()).andReturn(emailEnabled);
        if (!emailEnabled) {
            expect(approvalProfileSession.getApprovalProfile(APPROVALPROFILE2_ID)).andReturn(approvalProfile2);
            expect(endEntityProfileSession.getEndEntityProfileIdToNameMap()).andReturn(MapTools.unmodifiableMap(ENDENTITYPROFILE_ID, ENDENTITYPROFILE_NAME));
            expect(endEntityProfileSession.getEndEntityProfile(ENDENTITYPROFILE_ID)).andReturn(endEntityProfile);
        }
    }

    /**
     * Tests with approval profiles and an end entity profiles with notifications, but with e-mail unavailable.
     * This should result in two issues being reported from the configuration checker.
     */
    @Test
    public void getTicketsWithMisconfiguration() {
        log.trace(">getTicketsWithMisconfiguration");
        expectSteps(/*emailEnabled=*/false);
        replay(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        final ConfigurationIssue issue = new MissingEmailConfiguration(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        final List<Ticket> tickets = issue.getTickets();
        verify(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        assertEquals("Wrong number of tickets", 2, tickets.size());
        // Check messages
        assertEquals("(MISSING_EMAIL_CONFIGURATION_APPROVALPROFILE_TICKET_DESCRIPTION, " + APPROVALPROFILE1_NAME + ")", tickets.get(0).getTicketDescription().toString());
        assertEquals("(MISSING_EMAIL_CONFIGURATION_ENDENTITYPROFILE_TICKET_DESCRIPTION, " + ENDENTITYPROFILE_NAME + ")", tickets.get(1).getTicketDescription().toString());
        // Check access control of tickets
        reset(approvalProfileSession, endEntityProfileSession);
        final AuthenticationToken dummyAdmin = EasyMock.createStrictMock(AuthenticationToken.class);
        expect(approvalProfileSession.isAuthorizedToView(same(dummyAdmin), eq(APPROVALPROFILE1_ID))).andReturn(true);
        expect(endEntityProfileSession.isAuthorizedToView(same(dummyAdmin), eq(ENDENTITYPROFILE_ID))).andReturn(false);
        replay(approvalProfileSession, endEntityProfileSession);
        assertTrue("Should be authorized.", tickets.get(0).isAuthorizedToView(dummyAdmin));
        assertFalse("Should not be authorized.", tickets.get(1).isAuthorizedToView(dummyAdmin));
        verify(approvalProfileSession, endEntityProfileSession);
        log.trace("<getTicketsWithMisconfiguration");
    }

    /**
     * Tests with approval profiles and an end entity profiles with notifications, and with e-mail available
     * This should not result in any issues being reported.
     */
    @Test
    public void getTicketsWithCorrectConfiguration() {
        log.trace(">getTicketsWithCorrectConfiguration");
        expectSteps(/*emailEnabled=*/true);
        final ConfigurationIssue issue = new MissingEmailConfiguration(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        replay(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        final List<Ticket> tickets = issue.getTickets();
        verify(approvalProfileSession, endEntityProfileSession, isEmailConfigured);
        assertEquals("Wrong number of tickets", 0, tickets.size());
        log.trace("<getTicketsWithCorrectConfiguration");
    }
    
    @Test
    public void databaseValue() {
        log.trace(">databaseValue");
        assertEquals("The database value is not allowed to change.", "MissingEmailConfiguration",
                new MissingEmailConfiguration(null, null, null).getDatabaseValue());
        log.trace("<databaseValue");
    }
}
