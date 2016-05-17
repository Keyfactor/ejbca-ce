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

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Holds data of one approval step
 * 
 * @version $Id$
 */
public class ApprovalStep implements Serializable {

    private static final long serialVersionUID = 8652607031017119847L;
    
    private int stepId; // Equivalent to property key
    private String stepAuthorizationObject; // Equivalent to property value, for example, the AdminRole name
    private Map<Integer, ApprovalStepMetadata> metadata;
    private int requiredNumberOfApprovals;
    private boolean canSeePreviousSteps;
    private String notificationEmail;
    private List<Integer> previousStepsDependency;
    
    // Approval data
    private int approvalStatus;
    private int numberOfApprovals;
    
    public ApprovalStep(final int id, final String stepAuthObject, final int nrOfApprovals, 
            final boolean canSeePreviousSteps, final String email, final List<Integer> previousStepsDependency) {
        this.stepId = id;
        this.stepAuthorizationObject = stepAuthObject;
        this.metadata = new HashMap<Integer, ApprovalStepMetadata>();
        this.requiredNumberOfApprovals = nrOfApprovals;
        this.canSeePreviousSteps = canSeePreviousSteps;
        this.notificationEmail = email;
        this.previousStepsDependency = previousStepsDependency;
        this.approvalStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        this.numberOfApprovals = 0;
    }
    
    public ApprovalStep(final int id, final String stepAuthObject, final List<ApprovalStepMetadata> metadata, 
            final int nrOfApprovals, 
            final boolean canSeePreviousSteps, final String email, final List<Integer> previousStepsDependency) {
        this.stepId = id;
        this.stepAuthorizationObject = stepAuthObject;
        this.requiredNumberOfApprovals = nrOfApprovals;
        this.canSeePreviousSteps = canSeePreviousSteps;
        this.notificationEmail = email;
        this.previousStepsDependency = previousStepsDependency;
        this.approvalStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        this.numberOfApprovals = 0;
        
        this.metadata = new HashMap<Integer, ApprovalStepMetadata>();
        for(ApprovalStepMetadata md : metadata) {
            this.metadata.put(Integer.valueOf(md.getMetadataId()), md);
        }
    }
    
    public int getStepId() {
        return stepId;
    }
    
    public String getStepAuthorizationObject() {
        return stepAuthorizationObject;
    }
    
    public int getRequiredNumberOfApproval() {
        return requiredNumberOfApprovals;
    }
    
    public boolean canSeePreviousSteps() {
        return canSeePreviousSteps;
    }

    public Collection<ApprovalStepMetadata> getMetadata() {
        return metadata.values();
    }
    
    public void updateOneMetadataValue(final Integer metadataId, final String optionValue, final String optionNote) {
        ApprovalStepMetadata md = metadata.get(metadataId);
        md.setOptionValue(optionValue);
        md.setOptionNote(optionNote);
        metadata.put(metadataId, md);
    }
    
    public void updateOneMetadata(final ApprovalStepMetadata metadata) {
        this.metadata.put(metadata.getMetadataId(), metadata);
    }
    
    public String getNotificationEmail() {
        return notificationEmail;
    }
    
    public int getApprovalStatus() {
        return approvalStatus;
    }
    
    public List<Integer> getPreviousStepsDependency() {
        return previousStepsDependency;
    }
    
    public void setPreviousStepsDependency(final List<Integer> previousStepsDependency) {
        this.previousStepsDependency = previousStepsDependency;
    }
    
    public int getNumberOfApprovals() {
        return numberOfApprovals;
    }
    
    public void addApproval(final boolean approved) throws ApprovalException {
        if(numberOfApprovals >= requiredNumberOfApprovals) {
            throw new ApprovalException("Error already enough approvals have been done on this step.");
        }
        numberOfApprovals++;
        updateStepApprovalStatus(approved);
    }
    
    private void updateStepApprovalStatus(final boolean approved) {
        if(approved) {
            if(getNumberOfApprovals() == requiredNumberOfApprovals) {
                approvalStatus = ApprovalDataVO.STATUS_APPROVED;
            }
        } else {
            approvalStatus = ApprovalDataVO.STATUS_REJECTED;
        }
    }
} 
