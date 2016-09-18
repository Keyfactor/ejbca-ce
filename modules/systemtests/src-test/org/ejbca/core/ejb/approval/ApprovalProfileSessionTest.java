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

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;
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

    private static final Logger LOG = Logger.getLogger(ApprovalProfileSessionTest.class);

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
        LinkedHashMap<Object, Object> map = accumulativeApprovalProfile.getDataMap();
        LOG.info("accumulativeApprovalProfile: "+map);
        int profileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, accumulativeApprovalProfile);
        assertEquals("Couldn't set number of approvals required locally?", originalValue, accumulativeApprovalProfile.getNumberOfApprovalsRequired());
        try {
            int newValue = 4711;
            AccumulativeApprovalProfile savedProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            //Verify that the original value is what it is
            LOG.info("savedProfile: "+map);
            if (originalValue != savedProfile.getNumberOfApprovalsRequired()) {
                throw new IllegalStateException("Test cannot continue, test data was not persisted");
            }
            savedProfile.setNumberOfApprovalsRequired(newValue);
            approvalProfileSession.changeApprovalProfile(alwaysAllowToken, savedProfile);
            AccumulativeApprovalProfile updatedProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            assertEquals("Profile was not updated with new data.", newValue, updatedProfile.getNumberOfApprovalsRequired());
        } finally {
            approvalProfileSession.removeApprovalProfile(alwaysAllowToken, profileId);
        }
    }
    
    /**
     * Test the renameApprovalProfile method in ApprovalProfileSession
     * @throws ApprovalProfileDoesNotExistException 
     */
    @Test
    public void testRenameApprovalProfile() throws ApprovalProfileExistsException, AuthorizationDeniedException, ApprovalProfileDoesNotExistException {
        String profileName = "testRenameApprovalProfile";
        AccumulativeApprovalProfile accumulativeApprovalProfile = new AccumulativeApprovalProfile(profileName);
        int profileId = approvalProfileSession.addApprovalProfile(alwaysAllowToken, accumulativeApprovalProfile);
        try {
            String newName = "testRenameApprovalProfileNew";
            AccumulativeApprovalProfile originalProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            Map<Integer, String> originalMap = approvalProfileSession.getApprovalProfileIdToNameMap();
            // This checks that the name in the database column was changed
            assertEquals("Profile name form id mapping is not what it should be", profileName, originalMap.get(profileId));
            // This checks if the name in the actual profile XML was changed
            assertEquals("Profile name is not what it should be", profileName, originalProfile.getProfileName());
            approvalProfileSession.renameApprovalProfile(alwaysAllowToken, originalProfile, newName);
            AccumulativeApprovalProfile newProfile = (AccumulativeApprovalProfile) approvalProfileSession.getApprovalProfile(profileId);
            Map<Integer, String> newMap = approvalProfileSession.getApprovalProfileIdToNameMap();
            assertEquals("Profile name form id mapping is not what it should be", newName, newMap.get(profileId));
            assertEquals("Profile name is not what it should be", newName, newProfile.getProfileName());
            
        } finally {
            approvalProfileSession.removeApprovalProfile(alwaysAllowToken, profileId);
        }
    }

}
