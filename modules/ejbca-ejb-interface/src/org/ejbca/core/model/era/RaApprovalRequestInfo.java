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
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
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
    
    // Request information from ApprovalDataVO
    private final int id;
    private final int approvalCalculatedUniqueId; // to detect identical requests
    private final int approvalType;
    private final int caId;
    private final String caName; // to avoid unnecessary lookups. not present in ApprovalDataVO
    private final int endEntityProfileId;
    private final Date expireDate;
    private final int remainingApprovals;
    private final String requesterIssuerDN;
    private final String requesterSerialNumber;
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
    
    // Current approval step
    private final ApprovalStep nextApprovalStep;
    private ApprovalPartition relevantApprovalPartition;
    
    // Previous approval steps that are visible to the admin
    private final List<ApprovalStep> previousApprovalSteps;
    
    public RaApprovalRequestInfo(final AuthenticationToken authenticationToken, final String adminCertIssuer, final String adminCertSerial, final String caName, final ApprovalDataVO approval,
            final List<ApprovalDataText> requestData, final RaEditableRequestData editableData) {
        id = approval.getId();
        approvalCalculatedUniqueId = approval.getApprovalId();
        approvalType = approval.getApprovalType();
        caId = approval.getCAId();
        this.caName = caName;
        endEntityProfileId = approval.getEndEntityProfileiId();
        expireDate = approval.getExpireDate();
        remainingApprovals = approval.getRemainingApprovals();
        requesterIssuerDN = approval.getReqadmincertissuerdn();
        requesterSerialNumber = approval.getReqadmincertsn();
        final Certificate requesterCert = approval.getApprovalRequest().getRequestAdminCert();
        requesterSubjectDN = requesterCert != null ? CertTools.getSubjectDN(requesterCert) : null;
        requestDate = approval.getRequestDate();
        status = approval.getStatus();
        this.requestData = requestData;
        this.editableData = editableData;
        
        lastEditedByMe = approval.getApprovalRequest().isEditedByMe(authenticationToken);
        // TODO show the Subject DN (or common name) of the admins who have edited the request (ECA-) 
        
        // Check if approved by self
        approvedByMe = false;
        for (final Approval prevApproval : approval.getApprovals()) {
            if (authenticationToken.equals(prevApproval.getAdmin())) {
                approvedByMe = true;
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
        if (nextStep != null && status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL && !lastEditedByMe) {
            nextApprovalStep = nextStep;
        } else {
            nextApprovalStep = null;
        }

        relevantApprovalPartition = null;
        if(nextApprovalStep != null) {
            Map<Integer, ApprovalPartition> partitions = nextApprovalStep.getPartitions();
            for(ApprovalPartition partition : partitions.values()) {
                try {
                    if(approvalProfile.canApprovePartition(authenticationToken, partition)) {
                        relevantApprovalPartition = partition;
                        break;
                    }
                } catch (AuthenticationFailedException e) {
                    // If this admin cannot approve this partition, check the next partition
                }
            }
        }        
        
        // Previous steps
        final Collection<ApprovalStep> previousSteps = new ArrayList<>();
        // TODO get previous steps
        if (nextStep != null/* && nextStep.canSeePreviousSteps()*/) {
            // TODO check if we should check against currentApprovalStep.getPreviousStepsDependency()
            previousApprovalSteps = new ArrayList<>();
            for (final ApprovalStep step : previousSteps) {
                if (step.getStepIdentifier() < nextStep.getStepIdentifier()) {
                    previousApprovalSteps.add(step);
                }
            }
        } else {
            previousApprovalSteps = new ArrayList<>();
        }
        // TODO always add your own approval steps?
// TODO sort!
//        Collections.sort(previousApprovalSteps);
        
        requestedByMe = StringUtils.equals(requesterIssuerDN, adminCertIssuer) &&
                StringUtils.equalsIgnoreCase(requesterSerialNumber, adminCertSerial);
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
    
    public ApprovalPartition getRelevantApprovalPartition() {
        return relevantApprovalPartition;
    }
    
    public List<ApprovalStep> getPreviousApprovalSteps() {
        return previousApprovalSteps;
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
    
}