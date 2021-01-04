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
package org.ejbca.core.model.approval.profile;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.internal.InternalResources;
import org.cesecore.profiles.Profile;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PositiveIntegerValidator;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;

/**
 * This approval archetype represents the legacy method of approvals, i.e where a fixed number of administrators need to approve a request for it to 
 * pass.
 * 
 * @version $Id$
 */
public class AccumulativeApprovalProfile extends ApprovalProfileBase {

    public static final int FIXED_STEP_ID = 0; //Contains only a single sequence
    
    private static final long serialVersionUID = 6432620040542676563L;
    
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Note: do not change, may cause problems in deployed installations.
     */
    private static final String TYPE_IDENTIFIER = "ACCUMULATIVE_APPROVAL";
        
    public AccumulativeApprovalProfile() {
        //Public constructor needed deserialization 
        super();
    }

    public AccumulativeApprovalProfile(final String name) {
        super(name);
        initialize();
    }
    
    /*
     * This method only needs to be called by the factory method (and some unit tests), because it sets a ton of boilerplate stuff which isn't 
     * required by already initialized profiles.
     */
    @Override
    public void initialize() {
        super.initialize();
        //Workaround, since this profile normally doesn't allow adding sequences. 
        if (getSteps().isEmpty()) {
            getSteps().put(FIXED_STEP_ID, new ApprovalStep(FIXED_STEP_ID));
            addPartition(FIXED_STEP_ID);
            setFirstStep(FIXED_STEP_ID);
        }
    }


    @Override
    public String getApprovalProfileTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    public String getApprovalProfileLabel() {
        return intres.getLocalizedMessage("approval.profile.implementation.accumulative.approval.name");
    }

    public void setNumberOfApprovalsRequired(int approvalsRequired) throws PropertyValidationException {
        final int partitionIdentifier = getSinglePartitionIdentifier(FIXED_STEP_ID);
        DynamicUiProperty<? extends Serializable> approvalsRequiredProperty = getSteps().get(FIXED_STEP_ID).getPartition(partitionIdentifier)
                .getProperty(PROPERTY_NUMBER_OF_REQUIRED_APPROVALS);
        approvalsRequiredProperty.setValueGeneric(Integer.valueOf(approvalsRequired));
        addPropertyToPartition(FIXED_STEP_ID, partitionIdentifier, approvalsRequiredProperty);
        saveTransientObjects();
    }

    public int getNumberOfApprovalsRequired() {
        return getNumberOfApprovalsRequired(FIXED_STEP_ID, getSinglePartitionIdentifier(FIXED_STEP_ID));
    }
    
    private int getSinglePartitionIdentifier(final int stepIdentifier) {
        return getSteps().get(stepIdentifier).getPartitions().values().iterator().next().getPartitionIdentifier();
    }

    @Override
    public boolean isApprovalRequired() {
        return getNumberOfApprovalsRequired() > 0;
    }

    @Override
    public boolean canApprovalExecute(final Collection<Approval> approvalsPerformed) throws ApprovalException {
        //Verify that at least one of the approvals performed covers the single sequence in this implementation (Though it would be odd if they didn't)
        boolean sequenceAndPartitionFound = false;
        for(Approval approval : approvalsPerformed) {
            if(approval.getStepId() == FIXED_STEP_ID) {
                sequenceAndPartitionFound = true;
                break;
            }
        }
        if(!sequenceAndPartitionFound) {
            return false;
        } else {
            int numberofapprovalsleft = getRemainingApprovals(approvalsPerformed);
            if (numberofapprovalsleft < 0) {
                throw new ApprovalException("Approval cannot execute due to already being rejected.");
            }
            return numberofapprovalsleft == 0;
        }

    }

    @Override
    public int getRemainingApprovals(Collection<Approval> approvalsPerformed) {
        return getRemainingApprovalsInPartition(approvalsPerformed, FIXED_STEP_ID, getSinglePartitionIdentifier(FIXED_STEP_ID));
    }

    @Override
    public boolean isStepSizeFixed() {
        // Accumulative Approval Profiles can only have a single sequence
        return true;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return  AccumulativeApprovalProfile.class;
    }
    
    @Override
    protected ApprovalPartition addConstantProperties(ApprovalPartition approvalPartition) {
        DynamicUiProperty<Integer> numberOfRequiredApprovals = new DynamicUiProperty<>(PROPERTY_NUMBER_OF_REQUIRED_APPROVALS, 1);
        numberOfRequiredApprovals.setValidator(new PositiveIntegerValidator());
        approvalPartition.addProperty(numberOfRequiredApprovals);
        return approvalPartition;
    }

    @Override
    public boolean canApprovePartition(final AuthenticationToken authenticationToken, final ApprovalPartition approvalPartition) throws AuthenticationFailedException {
        // We all good here, homie. 
        return true;
    }
    
    @Override
    public boolean canAnyoneApprovePartition(final ApprovalPartition approvalPartition) {
        // Anyone can allow (given that their role has the needed access rules)
        return true;
    }
    
    @Override
    public List<String> getAllowedRoleNames(final ApprovalPartition approvalPartition) {
        return new ArrayList<>();
    }
    
    @Override
    public boolean canViewPartition(AuthenticationToken authenticationToken, ApprovalPartition approvalPartition)
            throws AuthenticationFailedException {
        return canApprovePartition(authenticationToken, approvalPartition);
    }

    @Override
    public int getOrdinalOfStepBeingEvaluated(Collection<Approval> approvalsPerformed) {
        return 1;
    }

    @Override
    public ApprovalStep getStepBeingEvaluated(Collection<Approval> approvalsPerformed) {
        return getStep(FIXED_STEP_ID);
    }
    
    @Override
    protected String[] getImplementationHiddenProperties() {
        return new String[]{PROPERTY_NUMBER_OF_REQUIRED_APPROVALS};
    }
    
    @Override
    public Set<String> getReadOnlyProperties() {
        return new HashSet<>();
    }

    @Override
    public boolean arePartitionsFixed() {
        return true;
    }

    @Override
    public boolean isPropertyPredefined(int stepIdentifier, int partitionIdentifier, String propertyName) {
        return super.isPropertyPredefined(stepIdentifier, partitionIdentifier, propertyName) || propertyName.equals(PROPERTY_NUMBER_OF_REQUIRED_APPROVALS);
    }

 
}
