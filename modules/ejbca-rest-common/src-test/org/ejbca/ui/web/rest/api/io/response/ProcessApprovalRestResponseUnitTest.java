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
package org.ejbca.ui.web.rest.api.io.response;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link ProcessApprovalRestResponse}.
 */
public class ProcessApprovalRestResponseUnitTest {

    private static final int STEP_ID = 1;
    private static final int PARTITION_ID_1 = 10;
    private static final int PARTITION_ID_2 = 20;
    private static final String APPROVAL_STATUS = "WAITING_FOR_APPROVAL";

    private ApprovalProfile createApprovalProfile() {
        return new AccumulativeApprovalProfile("testProfile");
    }

    /**
     * Verifies that buildStepPartition returns only the approval matching both stepId and partitionId,
     * not approvals belonging to a different partition in the same step.
     */
    @Test
    public void testBuildStepPartition_doesNotDuplicateApprovalAcrossPartitions() {
        // Given: an approval for partition 1, and we are building partition 2
        final Approval approvalForPartition1 = new Approval("comment", STEP_ID, PARTITION_ID_1);
        final ApprovalPartition partition2 = new ApprovalPartition(PARTITION_ID_2);
        final ApprovalProfile approvalProfile = createApprovalProfile();

        // When
        final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> result =
                ProcessApprovalRestResponse.buildStepPartition(
                        STEP_ID, partition2, Collections.singletonList(approvalForPartition1),
                        approvalProfile, APPROVAL_STATUS);

        // Then: no entries should be returned since the approval belongs to a different partition
        assertTrue("Expected no partition steps for a different partition, but got: " + result.size(), result.isEmpty());
    }

    /**
     * Verifies that buildStepPartition returns the approval when both stepId and partitionId match.
     */
    @Test
    public void testBuildStepPartition_returnsApprovalForMatchingPartition() {
        // Given: an approval for partition 1, and we are building partition 1
        final Approval approvalForPartition1 = new Approval("comment", STEP_ID, PARTITION_ID_1);
        final ApprovalPartition partition1 = new ApprovalPartition(PARTITION_ID_1);
        final ApprovalProfile approvalProfile = createApprovalProfile();

        // When
        final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> result =
                ProcessApprovalRestResponse.buildStepPartition(
                        STEP_ID, partition1, Collections.singletonList(approvalForPartition1),
                        approvalProfile, APPROVAL_STATUS);

        // Then: exactly one entry should be returned
        assertEquals("Expected one partition step for matching partition", 1, result.size());
    }

    /**
     * Verifies that when multiple approvals exist for different partitions in the same step,
     * each partition only receives its own approval.
     */
    @Test
    public void testBuildStepPartition_multiplePartitionsEachGetOwnApproval() {
        // Given: two approvals, one per partition
        final Approval approvalForPartition1 = new Approval("comment1", STEP_ID, PARTITION_ID_1);
        final Approval approvalForPartition2 = new Approval("comment2", STEP_ID, PARTITION_ID_2);
        final List<Approval> approvals = Arrays.asList(approvalForPartition1, approvalForPartition2);
        final ApprovalPartition partition1 = new ApprovalPartition(PARTITION_ID_1);
        final ApprovalPartition partition2 = new ApprovalPartition(PARTITION_ID_2);
        final ApprovalProfile approvalProfile = createApprovalProfile();

        // When
        final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> resultForPartition1 =
                ProcessApprovalRestResponse.buildStepPartition(STEP_ID, partition1, approvals, approvalProfile, APPROVAL_STATUS);
        final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> resultForPartition2 =
                ProcessApprovalRestResponse.buildStepPartition(STEP_ID, partition2, approvals, approvalProfile, APPROVAL_STATUS);

        // Then: each partition should have exactly one approval, not two
        assertEquals("Partition 1 should have exactly one approval", 1, resultForPartition1.size());
        assertEquals("Partition 2 should have exactly one approval", 1, resultForPartition2.size());
    }
}
