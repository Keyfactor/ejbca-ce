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
import java.util.ArrayList;
import java.util.List;

/**
 * Holds data of one approval step
 * 
 * @version $Id$
 */
public class ApprovalStep implements Serializable {

    private static final long serialVersionUID = 8652607031017119847L;
    
    public static final int METADATATYPE_CHECKBOX = 1;
    public static final int METADATATYPE_RADIOBUTTON = 2;
    public static final int METADATATYPE_TEXTBOX = 3;
    
    private int stepId; // Equivalent to property key
    private String stepAuthorizationObject; // Equivalent to property value, for example, the AdminRole name
    private ApprovalStepMetadata metadata;
    private int requiredNumberOfApprovals;
    private boolean canSeePreviousSteps;
    private String notificationEmail;
    private List<Integer> previousStepsDependency;
    
    // Approval data
    private int approvalStatus;
    private List<Approval> approvals;
    
    public ApprovalStep(final int id, final String stepAuthObject, final String instruction, 
            final List<String> options, final int optionsType, final int nrOfApprovals, 
            final boolean canSeePreviousSteps, final String email, final List<Integer> previousStepsDependency) {
        this.stepId = id;
        this.stepAuthorizationObject = stepAuthObject;
        this.metadata = new ApprovalStepMetadata(instruction, options, optionsType);
        this.requiredNumberOfApprovals = nrOfApprovals;
        this.canSeePreviousSteps = canSeePreviousSteps;
        this.notificationEmail = email;
        this.previousStepsDependency = previousStepsDependency;
        this.approvalStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        this.approvals = new ArrayList<Approval>();
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

    public ApprovalStepMetadata getMetadata() {
        return metadata;
    }
    
    public void updateMetadataValue(final String optionValue, final String optionNote) {
        metadata.setOptionValue(optionValue);
        metadata.setOptionNote(optionNote);
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
    
    public List<Approval> getApprovals() {
        return approvals;
    }
    
    public void addApproval(final Approval approval) {
        approvals.add(approval);
        updateApprovalStatus();
    }
    
    private void updateApprovalStatus() {
        int nrOfApprovals = 0;
        for(Approval approval : approvals) {
            if(approval.isApproved()) {
                nrOfApprovals++;
            }
        }
        if(nrOfApprovals == requiredNumberOfApprovals) {
            approvalStatus = ApprovalDataVO.STATUS_APPROVED;
        }
    }
} 
