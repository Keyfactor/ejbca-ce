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

package org.ejbca.core.ejb.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.junit.Test;

/**
 * System test for basic approval profile operations. 
 *  
 * @version $Id$
 *
 */

public class ApprovalProfileSessionTest {

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ApprovalProfileTest"));
    
    private ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);

    @Test
    public void addAccumulativeApprovalProfile() throws Exception {
        final String approvalProfileName = "AccumulativeApprovalProfile";
        int approvalProfileId = -1;
        try {
            final AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(approvalProfileName);
            approvalProfile.setNumberOfApprovalsRequired(2);
            approvalProfileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, approvalProfile);
            AccumulativeApprovalProfile addedApprovalProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(approvalProfileId);
            assertNotNull("AccumulativeApprovalProfile was not persisted correctly", addedApprovalProfile);
            assertEquals("AccumulativeApprovalProfile was not persisted correctly", 2, addedApprovalProfile.getNumberOfApprovalsRequired());
        } finally {
            if (approvalProfileId != -1) {
                approvalProfileSession.removeApprovalProfile(alwaysAllowToken, approvalProfileId);
            }
        }
    }
           
    /**
     * Test the changeApprovalProfile method in ApprovalProfileSession
     */
    @Test
    public void testChangeApprovalProfile() throws ApprovalProfileExistsException, AuthorizationDeniedException {
        int originalValue = 1337;
        String profileName = "testChangeApprovalProfile";
        AccumulativeApprovalProfile accumulativeApprovalProfile = new AccumulativeApprovalProfile(profileName);
        accumulativeApprovalProfile.setNumberOfApprovalsRequired(originalValue);
        int profileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, accumulativeApprovalProfile);
        try {
            int newValue = 4711;
            AccumulativeApprovalProfile originalProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            //Verify that the original value is what it is
            if (originalValue != originalProfile.getNumberOfApprovalsRequired()) {
                throw new IllegalStateException("Test cannot continue, test data was not persisted");
            }
            originalProfile.setNumberOfApprovalsRequired(newValue);
            approvalProfileSession.changeApprovalProfile(alwaysAllowToken, originalProfile);
            AccumulativeApprovalProfile updatedProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            assertEquals("Profile was not updated with new data.", newValue, updatedProfile.getNumberOfApprovalsRequired());
        } finally {
            approvalProfileSession.removeApprovalProfile(alwaysAllowToken, profileId);
        }
    }
}
