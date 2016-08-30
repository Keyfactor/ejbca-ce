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
package org.ejbca.core.model.approval;

import org.ejbca.core.model.approval.profile.ApprovalPartitionWorkflowState;
import org.ejbca.util.NotificationParamGen;


/**
 * Parameters for notification of partition owners in the approval request work flow.
 * 
 * ${approvalRequest.ID}            The approval request identifier.
 * ${approvalRequest.STEP_ID}       The approval step that this notification concerns.
 * ${approvalRequest.PARTITION_ID}  The approval partition in the step that this notification concerns.
 * ${approvalRequest.PARTITION_NAME} The approval partition in the step that this notification concerns.
 * ${approvalRequest.TYPE}          The type of approval request.
 * ${approvalRequest.WORKFLOWSTATE} The work flow state from the perspective of the one(s) responsible for handling the partition.
 * ${approvalRequest.REQUESTOR}     The human readable version of the authentication token that was used to create the request.
 * 
 * @see ApprovalPartitionWorkflowState
 * @version $Id$
 */
public class ApprovalNotificationParameterGenerator extends NotificationParamGen {

    public ApprovalNotificationParameterGenerator(final int approvalRequestId, final int approvalStepId, final int approvalPartitionId,
            final String approvalPartitionName, final String approvalType, final String workflowState, final String requestor) {
        paramPut("approvalRequest.ID", approvalRequestId);
        paramPut("approvalRequest.STEP_ID", approvalStepId);
        paramPut("approvalRequest.PARTITION_ID", approvalPartitionId);
        paramPut("approvalRequest.PARTITION_NAME", approvalPartitionName);
        paramPut("approvalRequest.TYPE", approvalType);
        paramPut("approvalRequest.WORKFLOWSTATE", workflowState);
        paramPut("approvalRequest.REQUESTOR", requestor);
    }

}
