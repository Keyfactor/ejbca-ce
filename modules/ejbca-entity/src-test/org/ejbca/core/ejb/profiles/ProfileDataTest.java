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
package org.ejbca.core.ejb.profiles;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.junit.Test;

/**
 * Unit tests for the ProfileData class
 * 
 * @version $Id$
 *
 */
public class ProfileDataTest {

    /**
     * This test creates a ProfileData object using an ApprovalProfile, then extracts the profile back out in order to verify integrity. 
     */
    @Test
    public void testApprovalProfile() {
        final int numberOfApprovalsRequired = 4711;
        final String profileName = "testApprovalProfile";
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile(profileName);
        approvalProfile.initialize();
        approvalProfile.setNumberOfApprovalsRequired(numberOfApprovalsRequired);
        ProfileData profileData = new ProfileData(0, approvalProfile);
        ApprovalProfile retrievedApprovalProfile = null;
        try {
            retrievedApprovalProfile = (ApprovalProfile) profileData.getProfile();
        } catch (ClassCastException e) {
            fail("Retrived Profile wasn't returned as an ApprovalProfile");
        }
        assertEquals("Profile name was lost during conversion", profileName, retrievedApprovalProfile.getProfileName());
        AccumulativeApprovalProfile recastProfile = null;
        try {
            recastProfile = (AccumulativeApprovalProfile) retrievedApprovalProfile;
        } catch (ClassCastException e) {
            fail("Retrieved profile was not instansiated as an " + AccumulativeApprovalProfile.class.getCanonicalName());
        }
        assertEquals("The number of required approvals was not retained.", numberOfApprovalsRequired, recastProfile.getNumberOfApprovalsRequired());
    }

}
