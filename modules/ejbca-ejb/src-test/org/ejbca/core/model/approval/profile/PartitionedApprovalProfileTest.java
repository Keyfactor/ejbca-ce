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
package org.ejbca.core.model.approval.profile;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.authentication.AuthenticationFailedException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.junit.Test;

/**
 * Unit tests for the PartitionedApprovalProfile class.
 * 
 * @version $Id$
 *
 */
public class PartitionedApprovalProfileTest {

    /**
     * Approval is required if there are any partitions that the ANYBODY pseudo-role doesn't have access to
     */
    @Test
    public void testCanApprovalExecute() throws ApprovalException, AuthenticationFailedException {
        //Create a profile with two steps, two partitions in each. 
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            approvalProfile.addPartition(approvalStep.getStepIdentifier());
        }
        List<Approval> approvals = new ArrayList<>();
        for (ApprovalStep step : approvalProfile.getSteps().values()) {
            for (ApprovalPartition partition : step.getPartitions().values()) {
                approvals.add(new Approval("", step.getStepIdentifier(), partition.getPartitionIdentifier()));
            }
        }
        assertFalse("No approvals submitted, check should have failed.", approvalProfile.canApprovalExecute(new ArrayList<Approval>()));
        assertFalse("Incorrect approvals submitted, check should have failed.",
                approvalProfile.canApprovalExecute(Arrays.asList(approvals.get(0), approvals.get(0), approvals.get(0), approvals.get(0))));
        assertTrue("Correct set of approvals submitted, check should have passed.", approvalProfile.canApprovalExecute(approvals));

    }

}
