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
package org.ejbca.core.model.era;

import java.io.Serializable;

import org.ejbca.core.model.approval.ApprovalRequest;

/**
 * Used for approving requests from RaManageRequestBean
 * @version $Id$
 */
public class RaApprovalResponseRequest implements Serializable {

    public static enum Action {
        SAVE,
        APPROVE,
        REJECT;
    }

    private static final long serialVersionUID = 1L;
    /** id of approval */
    private final int id;
    private final int stepIdentifier;
    private final int partitionIdentifier;
    private final ApprovalRequest approvalRequest;
    private final String comment;
    private final Action action;
    
    public RaApprovalResponseRequest(final int id, final int stepIdentifier, final int partitionIdentifier, final ApprovalRequest approvalRequest, final String comment, final Action action) {
        this.id = id;
        this.stepIdentifier = stepIdentifier;
        this.partitionIdentifier = partitionIdentifier;
        this.approvalRequest = approvalRequest;
        this.comment = comment;
        this.action = action;
    }

    public int getId() {
        return id;
    }
    public int getStepIdentifier() {
        return stepIdentifier;
    }
    
    public ApprovalRequest getApprovalRequest() {
        return approvalRequest;
    }

    public String getComment() {
        return comment;
    }
    
    public Action getAction() {
        return action;
    }

    public int getPartitionIdentifier() {
        return partitionIdentifier;
    }

}
