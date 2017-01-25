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
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.TimeAndAdmin;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

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
    private final String caName; // to avoid unnecessary lookups. only the id is present in ApprovalDataVO
    private final String requesterSubjectDN;
    private final int status;
    private final ApprovalDataVO approvalData;
    private final ApprovalProfile approvalProfile;
    private final long maxExtensionTime;
    private final String endEntityProfileName;
    private final EndEntityProfile endEntityProfile;
    private final String certificateProfileName;
    
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
    private final List<RaApprovalStepInfo> previousApprovalSteps;
    
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
    
    public RaApprovalRequestInfo(final AuthenticationToken authenticationToken, final String caName,
            final String endEntityProfileName, final EndEntityProfile endEntityProfile, final String certificateProfileName, final ApprovalProfile approvalProfileParam,
            final ApprovalDataVO approval, final List<ApprovalDataText> requestData, final RaEditableRequestData editableData) {
        id = approval.getId();
        this.caName = caName;
        final Certificate requesterCert = approval.getApprovalRequest().getRequestAdminCert();
        requesterSubjectDN = requesterCert != null ? CertTools.getSubjectDN(requesterCert) : null;
        status = approval.getStatus();
        this.approvalData = approval;
        this.requestData = requestData;
        this.endEntityProfile = endEntityProfile;
        this.endEntityProfileName = endEntityProfileName;
        this.certificateProfileName = certificateProfileName;
        this.editableData = editableData;
        
        final AuthenticationToken requestAdmin = approval.getApprovalRequest().getRequestAdmin();
        requestedByMe = requestAdmin != null && requestAdmin.equals(authenticationToken);
        lastEditedByMe = approval.getApprovalRequest().isEditedByMe(authenticationToken);
        editedByAdmins = approval.getApprovalRequest().getEditedByAdmins();
        
        // Check which partitions have been approved, and if approved by self
        approvedByMe = false;
        final Set<StepPartitionId> approvedSet = new HashSet<>();
        final Set<StepPartitionId> approvedByMeSet = new HashSet<>();
        for (final Approval prevApproval : approval.getApprovals()) {
            final StepPartitionId spId = new StepPartitionId(prevApproval.getStepId(), prevApproval.getPartitionId());
            approvedSet.add(spId);
            if (authenticationToken.equals(prevApproval.getAdmin())) {
                approvedByMe = true;
                approvedByMeSet.add(spId);
            }
        }
        
        // Can only edit approvals in waiting state that haven't been approved by any admin yet
        editable = (status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL && approval.getApprovals().isEmpty());
        
        // The profile contains information about the approval steps
        approvalProfile = approvalProfileParam != null ? approvalProfileParam : approval.getApprovalProfile();
        if (approvalProfile != null) {
            maxExtensionTime = approvalProfile.getMaxExtensionTime();
        } else {
            maxExtensionTime = EjbcaConfiguration.getApprovalDefaultMaxExtensionTime();
        }
        
        
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
        
        // Build a list of all approval steps that we are allowed to see (used in the RA GUI to display the previous steps/partitions)
        stepToOrdinalMap = new HashMap<>();
        previousApprovalSteps = new ArrayList<>();
        ApprovalStep step = approvalProfile.getFirstStep();
        int stepOrdinal = 1;
        while (step != null) {
            final int stepId = step.getStepIdentifier();
            stepToOrdinalMap.put(stepId, stepOrdinal);
            
            final List<ApprovalPartition> partitions = new ArrayList<>();
            for (final ApprovalPartition partition : step.getPartitions().values()) {
                try {
                    final StepPartitionId spId = new StepPartitionId(stepId, partition.getPartitionIdentifier());
                    if (approvedByMeSet.contains(spId) || (approvalProfile.canViewPartition(authenticationToken, partition) && approvedSet.contains(spId))) {
                        partitions.add(partition);
                    }
                } catch (AuthenticationFailedException e) {
                    // Just ignore
                }
            }
            if (!partitions.isEmpty()) {
                previousApprovalSteps.add(new RaApprovalStepInfo(stepId, partitions));
            }
            
            final Integer nextStepId = step.getNextStep();
            if (nextStepId == null) { break; }
            step = approvalProfile.getStep(nextStepId);
            stepOrdinal++;
        }
    }

    public int getId() {
        return id;
    }
    
    public String getCaName() {
        return caName;
    }
    
    public int getStatus() {
        return status;
    }
    
    public String getRequesterSubjectDN() {
        return requesterSubjectDN;
    }
    
    public ApprovalDataVO getApprovalData() {
        return approvalData;
    }
    
    public ApprovalRequest getApprovalRequest() {
        return approvalData.getApprovalRequest();
    }
    
    public EndEntityProfile getEndEntityProfile() {
        return endEntityProfile;
    }
    
    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }
    
    public String getCertificateProfileName() {
        return certificateProfileName;
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
    
    /** @since EJBCA 6.7.0. If the response comes from an earlier version, it will return 0 (=extension of requests not allowed) */
    public long getMaxExtensionTime() {
        return maxExtensionTime;
    }
    
    public ApprovalStep getNextApprovalStep() {
        return nextApprovalStep;
    }
    
    public ApprovalPartition getNextApprovalStepPartition() {
        return nextApprovalStepPartition;
    }
    
    public List<RaApprovalStepInfo> getPreviousApprovalSteps() {
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
    public boolean isWaitingForMe(final AuthenticationToken admin) {
        if (requestedByMe) {
            // There are approval types that do not get executed automatically on approval.
            // These go into APPROVED (instead of EXECUTED) state and need to executed again by the requester
            return status == ApprovalDataVO.STATUS_APPROVED;
        } else if (approvedByMe) {
            return false; // Already approved by me, so not "waiting for me"
        } else {
            if(status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
                try {
                    if(approvalProfile.canApprovePartition(admin, nextApprovalStepPartition)) {
                        return true;
                    }
                } catch (AuthenticationFailedException e) { }
            }
        }
        return false;
    }
    
    /** Is waiting for someone else to do something */
    public boolean isPending(final AuthenticationToken admin) {
        return !isWaitingForMe(admin) && !isProcessed();
    }
    
    public boolean isExpired(final Date now) {
        return approvalData.getExpireDate().before(now) && !isProcessed();
    }
    
    public boolean isProcessed() {
        return status != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL && 
               status != ApprovalDataVO.STATUS_APPROVED &&
               status != ApprovalDataVO.STATUS_EXPIRED &&
               status != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
    }
    
    public boolean isWaitingForFirstApproval(final Date now) {
        return !isProcessed() && !isExpired(now) && approvalData.getApprovals().isEmpty();
    }
    
    public boolean isInProgress(final Date now) {
        return !isProcessed() && !isExpired(now) && !approvalData.getApprovals().isEmpty();
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