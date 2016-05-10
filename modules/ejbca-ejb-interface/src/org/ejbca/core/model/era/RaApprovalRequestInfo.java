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
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.approval.ApprovalDataVO;

/**
 * Information for an approval request.
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
    private final int endEntityProfileId;
    private final Date expireDate;
    private final int remainingApprovals;
    private final String requesterIssuerDN;
    private final String requesterSerialNumber;
    private final Date requestDate;
    private final int status;
    
    private final boolean requestedByMe;
    
    // Request information from Request
    // TODO do we need any info from this?
    
    // Approval Profile information
    // TODO do we need any info from this?
    
    public RaApprovalRequestInfo(final String adminCertIssuer, final String adminCertSerial, final ApprovalDataVO approval) {
        id = approval.getId();
        approvalCalculatedUniqueId = approval.getApprovalId();
        approvalType = approval.getApprovalType();
        caId = approval.getCAId();
        endEntityProfileId = approval.getEndEntityProfileiId();
        expireDate = approval.getExpireDate();
        remainingApprovals = approval.getRemainingApprovals();
        requesterIssuerDN = approval.getReqadmincertissuerdn();
        requesterSerialNumber = approval.getReqadmincertsn();
        requestDate = approval.getRequestDate();
        status = approval.getStatus();
        
        //final ApprovalProfile profile = approval.getApprovalRequest().getApprovalProfile();
        //profile.get
        
        //approval.getApprovals();
        //approval.getApprovalRequest().
        
        requestedByMe = StringUtils.equals(requesterIssuerDN, adminCertIssuer) &&
                StringUtils.equalsIgnoreCase(requesterSerialNumber, adminCertSerial);
    }
    
    public int getId() {
        return id;
    }
    
    public Date getRequestDate() {
        return requestDate;
    }
    
    public int getCAId() {
        return caId;
    }
    
    public int getStatus() {
        return status;
    }
    
    public int getType() {
        return approvalType;
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
