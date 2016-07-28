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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;

/**
 * Information for an approval request, as seen by an admin.
 * 
 * @version $Id$
 */
public class RaApprovalRequestInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaApprovalRequestInfo.class);
    
    // Request information from ApprovalDataVO
    private final int id;
    private final int approvalCalculatedUniqueId; // to detect identical requests
    private final int approvalType;
    private final int caId;
    private final String caName; // to avoid unnecessary lookups. not present in ApprovalDataVO
    private final int endEntityProfileId;
    private final Date expireDate;
    private final int remainingApprovals;
    private final String requesterSubjectDN;
    private final Date requestDate;
    private final int status;
    private final ApprovalProfile approvalProfile;
    
    /** Request data, as text. Not editable */
    private final List<ApprovalDataText> requestData;
    /** Editable request data for end entity requests */
    private final RaEditableRequestData editableData;
    
    private final boolean requestedByMe;
    private final boolean lastEditedByMe;
    private boolean approvedByMe;
    private final boolean editable;
    private final List<TimeAndAdmin> editedByAdmins;
    
    // Current approval step
    private ApprovalStep nextApprovalStep;
    private ApprovalPartition nextApprovalStepPartition;
    private int currentStepOrdinal;
    private Collection<String> nextStepAllowedRoles;
    
    // Previous approval steps that are visible to the admin
    private final List<ApprovalStep> previousApprovalSteps;
    
    private final Map<Integer,Integer> stepToOrdinalMap;
    
    private static class StepPartitionId {
        final int stepId;
        final int partitionId;
        StepPartitionId(final int stepId, final int partitionId) {
            this.stepId = stepId;
            this.partitionId = partitionId;
        }
        @Override
        public boolean equals(final Object other) {
            if (other instanceof StepPartitionId) {
                final StepPartitionId o = (StepPartitionId)other;
                return o.stepId == stepId && o.partitionId == partitionId;
            }
            return false;
        }
        @Override
        public int hashCode() {
            return stepId ^ (partitionId << 16);
        }
    }
    
    public RaApprovalRequestInfo(final AuthenticationToken authenticationToken, final String caName, final ApprovalDataVO approval,
            final List<ApprovalDataText> requestData, final RaEditableRequestData editableData) {
        id = approval.getId();
        approvalCalculatedUniqueId = approval.getApprovalId();
        approvalType = approval.getApprovalType();
        caId = approval.getCAId();
        this.caName = caName;
        endEntityProfileId = approval.getEndEntityProfileiId();
        expireDate = approval.getExpireDate();
        remainingApprovals = approval.getRemainingApprovals();
        final Certificate requesterCert = approval.getApprovalRequest().getRequestAdminCert();
        requesterSubjectDN = requesterCert != null ? CertTools.getSubjectDN(requesterCert) : null;
        requestDate = approval.getRequestDate();
        status = approval.getStatus();
        this.requestData = requestData;
        this.editableData = editableData;
        
        final AuthenticationToken requestAdmin = approval.getApprovalRequest().getRequestAdmin();
        requestedByMe = requestAdmin != null && requestAdmin.equals(authenticationToken);
        lastEditedByMe = approval.getApprovalRequest().isEditedByMe(authenticationToken);
        editedByAdmins = approval.getApprovalRequest().getEditedByAdmins();
        // TODO show the Subject DN (or common name) of the admins who have edited the request (ECA-) 
        
        // Check if approved by self
        approvedByMe = false;
        final Set<StepPartitionId> approvedByMeSet = new HashSet<>();
        for (final Approval prevApproval : approval.getApprovals()) {
            if (authenticationToken.equals(prevApproval.getAdmin())) {
                approvedByMe = true;
                approvedByMeSet.add(new StepPartitionId(prevApproval.getStepId(), prevApproval.getPartitionId()));
            }
        }
        
        // Can only edit approvals in waiting state that haven't been approved by any admin yet
        editable = (status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL && approval.getApprovals().isEmpty());
        
        // The profile contains information about the approval steps
        approvalProfile = approval.getApprovalProfile();
        
        // Next steps
        final ApprovalStep nextStep;
        try {
            nextStep = approvalProfile.getStepBeingEvaluated(approval.getApprovals());
        } catch (AuthenticationFailedException e) {
            throw new IllegalStateException(e);
        }
        
        nextApprovalStep = null;
        nextApprovalStepPartition = null;
        if (nextStep != null && status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL && !lastEditedByMe) {
            final Map<Integer, ApprovalPartition> partitions = nextStep.getPartitions();
            for (ApprovalPartition partition : partitions.values()) {
                try {
                    if (approvalProfile.canApprovePartition(authenticationToken, partition)) {
                        nextApprovalStep = nextStep;
                        nextApprovalStepPartition = partition;
                        break;
                    }
                } catch (AuthenticationFailedException e) {
                    // If this admin cannot approve this partition, check the next partition
                }
            }
        }
        try {
            currentStepOrdinal = approvalProfile.getOrdinalOfStepBeingEvaluated(approval.getApprovals());
        } catch (AuthenticationFailedException e) {
            // Should never happen
            log.debug("Exception occurred while getting current step", e);
            currentStepOrdinal = -1;
        }
        
        // Determine which admins can approve the next step (ECA-5123)
        nextStepAllowedRoles = new HashSet<>();
        if (nextStep != null) {
            for (final ApprovalPartition partition : nextStep.getPartitions().values()) {
                nextStepAllowedRoles.addAll(approvalProfile.getAllowedRoleNames(partition));
            }
        }
        
        // Previous steps
        final List<Integer> allStepIds = new ArrayList<>(approvalProfile.getSteps().keySet());
        Collections.sort(allStepIds);
        previousApprovalSteps = new ArrayList<>();
        stepToOrdinalMap = new HashMap<>();
        int stepOrdinal = 0;
        for (final int stepId : allStepIds) {
            stepToOrdinalMap.put(stepId, ++stepOrdinal);
            if (nextStep != null && stepId <= nextStep.getStepIdentifier()) {
                final ApprovalStep step = approvalProfile.getSteps().get(stepId);
                final Map<Integer, ApprovalPartition> partitions = nextStep.getPartitions();
                for (ApprovalPartition partition : partitions.values()) {
                    try {
                        final StepPartitionId spId = new StepPartitionId(step.getStepIdentifier(), partition.getPartitionIdentifier());
                        if (approvedByMeSet.contains(spId) || approvalProfile.canViewPartition(authenticationToken, partition)) {
                            previousApprovalSteps.add(step);
                            break;
                        }
                    } catch (AuthenticationFailedException e) {
                        // If this admin cannot approve this partition, check the next partition
                    }
                }
            }
        }
    }

    public int getId() {
        return id;
    }
    
    public Date getRequestDate() {
        return requestDate;
    }
    
    public int getCaId() {
        return caId;
    }
    
    public String getCaName() {
        return caName;
    }
    
    public int getStatus() {
        return status;
    }
    
    public int getType() {
        return approvalType;
    }
    
    public String getRequesterSubjectDN() {
        return requesterSubjectDN;
    }
    
    public List<ApprovalDataText> getRequestData() {
        return requestData;
    }
    
    public RaEditableRequestData getEditableData() {
        return editableData.clone();
    }
    
    public ApprovalProfile getApprovalProfile() {
        return approvalProfile;
    }
    
    public ApprovalStep getNextApprovalStep() {
        return nextApprovalStep;
    }
    
    public ApprovalPartition getNextApprovalStepPartition() {
        return nextApprovalStepPartition;
    }
    
    public List<ApprovalStep> getPreviousApprovalSteps() {
        return previousApprovalSteps;
    }
    
    public Map<Integer,Integer> getStepIdToOrdinalMap() {
        return stepToOrdinalMap;
    }
    
    public int getStepCount() {
        return stepToOrdinalMap.size();
    }
    
    public int getCurrentStepOrdinal() {
        return currentStepOrdinal;
    }
    
    public Collection<String> getNextStepAllowedRoles() {
        return nextStepAllowedRoles;
    }
    
    /** Is waiting for the given admin to do something */
    public boolean isWaitingForMe() {
        if (requestedByMe) {
            // There are approval types that do not get executed automatically on approval.
            // These go into APPROVED (instead of EXECUTED) state and need to executed again by the requester
            return status == ApprovalDataVO.STATUS_APPROVED;
        } else if (approvedByMe) {
            return false; // Already approved by me, so not "waiting for me"
        } else {
            // TODO need to check if I can approve this. or does the query method do that?
            return status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        }
    }
    
    /** Is waiting for someone else to do something */
    public boolean isPending() {
        if (requestedByMe || approvedByMe) {
            // Pending if waiting for other admins to approve it
            return status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        } else {
            // If the request is in APPROVED state in this case, then another admin must execute it again manually for it to go through. 
            return status == ApprovalDataVO.STATUS_APPROVED;
        }
    }
    
    public boolean isProcessed() {
        return (status == ApprovalDataVO.STATUS_EXECUTED || 
                status == ApprovalDataVO.STATUS_EXECUTIONDENIED ||
                status == ApprovalDataVO.STATUS_EXECUTIONFAILED ||
                status == ApprovalDataVO.STATUS_REJECTED) &&
                (requestedByMe || lastEditedByMe || approvedByMe);
    }
    
    public boolean isRequestedByMe() {
        return requestedByMe;
    }
    
    public boolean isApprovedByMe() {
        return approvedByMe;
    }
    
    public boolean isEditedByMe() {
        return lastEditedByMe;
    }
    
    public boolean isEditable() {
        return editable;
    }
    
    public List<TimeAndAdmin> getEditedByAdmin() {
        return editedByAdmins;
    }
    
}