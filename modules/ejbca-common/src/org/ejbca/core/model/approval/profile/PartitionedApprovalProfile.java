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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.RoleInformation;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.DynamicUiPropertyCallback;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.profiles.Profile;

/**
 * PartitionedApprovalProfile represents an approval archetype where each approval is partitioned into several subtasks, assigned to one or more roles. 
 * 
 * @version $Id$
 *
 */
public class PartitionedApprovalProfile extends ApprovalProfileBase {

    private static final long serialVersionUID = 6991912129797327010L;
        
    private static final InternalResources intres = InternalResources.getInstance();
    
    public static final RoleInformation ANYBODY = new RoleInformation(-1, "Anybody", new ArrayList<AccessUserAspectData>());
    
    public static final int EXECUTION_STEP_ID = 0;
    public static final String PROPERTY_NAME = "name";
    public static final String PROPERTY_ROLES_WITH_APPROVAL_RIGHTS = "roles_with_approval_rights";

    {
        //Default step, which is the default execution step. It contains a single partition, and only a list of approved executors. 
        ApprovalStep executionStep = new ApprovalStep(EXECUTION_STEP_ID);
        addStep(executionStep);
        setFirstStep(executionStep.getStepIdentifier());
    }

    /**
     * Note: do not change, may cause problems in deployed installations.
     */
    private static final String TYPE_IDENTIFIER = "PARTITIONED_APPROVAL";

    public PartitionedApprovalProfile() {
        //Public constructor needed deserialization 
        super();
    }

    public PartitionedApprovalProfile(final String name) {
        super(name);
    }

    @Override
    public String getApprovalProfileLabel() {
        return intres.getLocalizedMessage("approval.profile.implementation.partitioned.approval.name");
    }

    @Override
    public String getApprovalProfileIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    public boolean isApprovalRequired() {
        //There is always at least one step with at least one partition, so always
        return true;
    }

    @Override
    public boolean canApprovalExecute(final Collection<Approval> approvalsPerformed) throws ApprovalException, AuthenticationFailedException {
        // Walk through all steps and their respective partitions, verify that the collection of approvals satisfies them. 
        ApprovalStep step = getFirstStep();
        while(step != null) {
            if(!isStepSatisfied(step, approvalsPerformed)) {
                return false;
            }
            step = getStep(step.getNextStep());
            if(step != null && step.equals(getFirstStep())) {
                throw new IllegalStateException("Approval steps have begun referencing each other as a circular array.");
            }
        }
        return true;
    }
    
    @Override
    public int getOrdinalOfStepBeingEvaluated(Collection<Approval> approvalsPerformed) throws AuthenticationFailedException {
        ApprovalStep step = getFirstStep();
        int i = 1;
        while(step != null) {
            if(!isStepSatisfied(step, approvalsPerformed)) {
                return i;
            } else {
                i++;
                step = getStep(step.getNextStep());
                if (step != null && step.equals(getFirstStep())) {
                    throw new IllegalStateException("Approval steps have begun referencing each other as a circular array.");
                }
            }
        }
        return -1;
    }
    
    @Override
    public ApprovalStep getStepBeingEvaluated(Collection<Approval> approvalsPerformed) throws AuthenticationFailedException {
        ApprovalStep step = getFirstStep();
        while(step != null) {
            if(!isStepSatisfied(step, approvalsPerformed)) {
                return step;
            } else {
                step = getStep(step.getNextStep());
                if (step != null && step.equals(getFirstStep())) {
                    throw new IllegalStateException("Approval steps have begun referencing each other as a circular array.");
                }
            }
        }
        return null;
    }
    
    @Override
    public boolean canApprovePartition(final AuthenticationToken authenticationToken, final ApprovalPartition approvalPartition) throws AuthenticationFailedException {
        @SuppressWarnings("unchecked")
        List<RoleInformation> roles = (List<RoleInformation>) approvalPartition.getProperty(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS).getValues();
        for (RoleInformation role : roles) {
            if (role.equals(ANYBODY)) {
                return true;
            } else {
                for (AccessUserAspectData accessUserAspect : role.getAccessUserAspects()) {
                    if (authenticationToken.matchIdentity(accessUserAspect)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }    

    @Override
    public int getRemainingApprovals(Collection<Approval> approvalsPerformed) {
        //Return the total number of partitions lacking approval, minus the number of approvals performed (presume that no approvals performed overlap) 
        int numberOfPartitions = 0;
        for(ApprovalStep approvalStep : getSteps().values()) {
            numberOfPartitions += approvalStep.getPartitions().size();
        }  
        return numberOfPartitions - approvalsPerformed.size();
    }

    @Override
    public boolean isStepSizeFixed() {
        // Partitioned Approval Profiles can have as many steps as you like. 
        return false;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return PartitionedApprovalProfile.class;
    }

    @Override
    protected ApprovalPartition addConstantProperties(ApprovalPartition approvalPartition) {
        //All partitions for this profile have some default fields: a name and a list of Roles with access 
        approvalPartition.addProperty(new DynamicUiProperty<String>(PROPERTY_NAME, ""));
        //Add "Anybody" as the default Role. 
        DynamicUiProperty<RoleInformation> roles = new DynamicUiProperty<RoleInformation>(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, ANYBODY,
                new ArrayList<RoleInformation>());
        //Will make this property into a multi-select instead of single select.
        roles.setHasMultipleValues(true);
        //Tell whatever bean is using this property to fill it with authorized roles. 
        roles.setPropertyCallback(DynamicUiPropertyCallback.ROLES);
        approvalPartition.addProperty(roles);
        return approvalPartition;
    }

    @Override
    public Set<String> getHiddenProperties() {
        return new HashSet<>(Arrays.asList(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS));
    }

}
