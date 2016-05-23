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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalStep;

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
    private final Date requestDate;
    private final int status;
    
    // Request data, as text
    private final List<ApprovalDataText> requestData;
    
    private final boolean requestedByMe;
    
    // Current approval step
    private final ApprovalStep nextApprovalStep;
    
    // Previous approval steps that are visible to the admin
    private final List<ApprovalStep> previousApprovalSteps;
    
    public RaApprovalRequestInfo(final AuthenticationToken authenticationToken, final String adminCertIssuer, final String adminCertSerial, final String caName, final ApprovalDataVO approval, final List<ApprovalDataText> requestData) {
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
        requestDate = approval.getRequestDate();
        status = approval.getStatus();
        this.requestData = requestData;
        
        // Next steps
        final ApprovalStep nextStep;
        nextStep = approval.getApprovalRequest().getNextUnhandledApprovalStepByAdmin(authenticationToken);
        if (nextStep != null && status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            nextApprovalStep = nextStep;
        } else {
            nextApprovalStep = null;
        }
            
        // Previous steps
        if (nextStep != null && nextStep.canSeePreviousSteps()) {
            // TODO check if we should check against currentApprovalStep.getPreviousStepsDependency()
            final List<ApprovalStep> steps = new ArrayList<>(approval.getApprovalRequest().getApprovalSteps().values());
            previousApprovalSteps = new ArrayList<>();
            for (final ApprovalStep step : steps) {
                if (step.getStepId() < nextStep.getStepId()) {
                    previousApprovalSteps.add(step);
                }
            }
        } else {
            previousApprovalSteps = new ArrayList<>();
        }
        // TODO always add your own approval steps?
        Collections.sort(previousApprovalSteps);
        
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
    
    public List<ApprovalDataText> getRequestData() {
        return requestData;
    }
    
    public ApprovalStep getNextApprovalStep() {
        return nextApprovalStep;
    }
    
    public List<ApprovalStep> getPreviousApprovalSteps() {
        return previousApprovalSteps;
    }
    
    /** Is waiting for the given admin to do something */
    public boolean isWaitingForMe() {
        if (requestedByMe) {
            return status == ApprovalDataVO.STATUS_APPROVED;
        } else {
            // TODO need to check if I can approve this. or does the query method do that?
            return status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        }
    }
    
    /** Is waiting for someone else to do something */
    public boolean isPending() {
        if (requestedByMe) {
            return status == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        } else {
            // TODO need to check if I have approved this
            return status == ApprovalDataVO.STATUS_APPROVED;
        }
    }
    
    // TODO should there be a "not requested by me, but waiting for someone else" status also? on the other hand, one can use the adminweb for that. or the "all" tab.
    //      and perhaps we should rename the "all" tab to "custom search"?
    
    
    // TODO add more methods here. try to not expose to much implementation details and to be JSF-friendly
    
}
