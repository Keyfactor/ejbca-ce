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

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.member.RoleMember;
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
        
    private static final Logger log = Logger.getLogger(PartitionedApprovalProfile.class);

    private static final InternalResources intres = InternalResources.getInstance();
    
    public static final RoleInformation ANYBODY = RoleInformation.fromRoleMembers(-1, null, "Anybody", new ArrayList<RoleMember>());
    
    public static final int EXECUTION_STEP_ID = 0;
    public static final String PROPERTY_NAME = "name";
    public static final String PROPERTY_ROLES_WITH_APPROVAL_RIGHTS = "roles_with_approval_rights";
    public static final String PROPERTY_ROLES_WITH_VIEW_RIGHTS = "roles_with_view_rights";
    
    private static final Set<String> predefinedProperties = new HashSet<>(Arrays.asList(PROPERTY_NAME, PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, PROPERTY_ROLES_WITH_VIEW_RIGHTS));

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
        initialize();
    }
    
    /*
     * This method only needs to be called by the factory method (and some unit tests), because it sets a ton of boilerplate stuff which isn't 
     * required by already initialized profiles.
     */
    @Override
    public void initialize() {
        super.initialize();
        //Default step, which is the default execution step. It contains a single partition, and only a list of approved executors. 
        ApprovalStep executionStep = new ApprovalStep(EXECUTION_STEP_ID);
        addStep(executionStep);
        setFirstStep(executionStep.getStepIdentifier());
    }

    @Override
    public String getApprovalProfileLabel() {
        return intres.getLocalizedMessage("approval.profile.implementation.partitioned.approval.name");
    }

    @Override
    public String getApprovalProfileTypeIdentifier() {
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
        if(approvalPartition != null) {
            @SuppressWarnings("unchecked")
            List<RoleInformation> roles = (List<RoleInformation>) approvalPartition.getProperty(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS).getValues();
            for (RoleInformation role : roles) {
                if (log.isTraceEnabled()) {
                    log.trace("Checking if authenticationToken '"+authenticationToken+"' matches role "+role.getName());
                }
                if (role.equals(ANYBODY)) {
                    return true;
                } else {
                    // Check if authenticationToken matches any of the AccessUserAspects that existed in the Role when the ApprovalProfile was saved.
                    for (final AccessUserAspect accessUserAspect : role.getAccessUserAspects()) {
                        if (authenticationToken.matches(accessUserAspect)) {
                            return true;
                        }
                    }
                }
            }
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Approval partition is null, canApprovePartition returns false for authenticationToken "+authenticationToken);
            }
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Administrator '"+authenticationToken+"' does not belong to a role that can approve partition "+approvalPartition.getPartitionIdentifier());
        }
        return false;
    }
    
    @Override
    public boolean canAnyoneApprovePartition(final ApprovalPartition approvalPartition) {
        @SuppressWarnings("unchecked")
        final List<RoleInformation> roles = (List<RoleInformation>) approvalPartition.getProperty(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS).getValues();
        for (final RoleInformation role : roles) {
            if (role.equals(ANYBODY)) {
                return true;
            }
        }
        return false;
    }
    
    @Override
    public List<String> getAllowedRoleNames(final ApprovalPartition approvalPartition) {
        final List<String> ret = new ArrayList<>();
        @SuppressWarnings("unchecked")
        final List<RoleInformation> roles = (List<RoleInformation>) approvalPartition.getProperty(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS).getValues();
        for (final RoleInformation role : roles) {
            ret.add(role.getName());
        }
        return ret;
    }
    
    @Override
    public boolean canViewPartition(AuthenticationToken authenticationToken, ApprovalPartition approvalPartition)
            throws AuthenticationFailedException {
        boolean result = false;
        @SuppressWarnings("unchecked")
        List<RoleInformation> roles = (List<RoleInformation>) approvalPartition.getProperty(PROPERTY_ROLES_WITH_VIEW_RIGHTS).getValues();
        for (RoleInformation role : roles) {
            if (role.equals(ANYBODY)) {
                result = true;
            } else {
                // Check if authenticationToken matches any of the AccessUserAspects that existed in the Role when the ApprovalProfile was saved.
                for (final AccessUserAspect accessUserAspect : role.getAccessUserAspects()) {
                    if (authenticationToken.matches(accessUserAspect)) {
                        result = true;
                    }
                }
            }
        }
        return result || canApprovePartition(authenticationToken, approvalPartition);
    }

    @Override
    public int getRemainingApprovals(Collection<Approval> approvalsPerformed) {
        //Return the total number of partitions lacking approval, minus the number of approvals performed (presume that no approvals performed overlap) 
        int remainingApprovalsInAllPartitions = 0;
        for (final ApprovalStep approvalStep : getSteps().values()) {
            for (final ApprovalPartition approvalPartition : approvalStep.getPartitions().values()) {
                remainingApprovalsInAllPartitions += getRemainingApprovalsInPartition(approvalsPerformed, approvalStep.getStepIdentifier(), approvalPartition.getPartitionIdentifier());
            }
        }  
        return remainingApprovalsInAllPartitions;
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
        
        //Add approving roles, with "Anybody" as the default Role. 
        DynamicUiProperty<RoleInformation> approvalRoles = new DynamicUiProperty<RoleInformation>(PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, ANYBODY,
                new HashSet<RoleInformation>());
        //Will make this property into a multi-select instead of single select.
        approvalRoles.setHasMultipleValues(true);
        //Tell whatever bean is using this property to fill it with authorized roles. 
        approvalRoles.setPropertyCallback(DynamicUiPropertyCallback.ROLES);
        approvalPartition.addProperty(approvalRoles);
        
        //Add roles with view rights, with "Anybody" as the default Role. 
        DynamicUiProperty<RoleInformation> viewRoles = new DynamicUiProperty<RoleInformation>(PROPERTY_ROLES_WITH_VIEW_RIGHTS, ANYBODY,
                new HashSet<RoleInformation>());
        //Will make this property into a multi-select instead of single select.
        viewRoles.setHasMultipleValues(true);
        //Tell whatever bean is using this property to fill it with authorized roles. 
        viewRoles.setPropertyCallback(DynamicUiPropertyCallback.ROLES);
        approvalPartition.addProperty(viewRoles);        
        return approvalPartition;
    }

    @Override
    protected String[] getImplementationHiddenProperties() {
        return new String[]{PROPERTY_NAME, PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, PROPERTY_ROLES_WITH_VIEW_RIGHTS};
    }
    

    @Override
    public Set<String> getReadOnlyProperties() {
        return new HashSet<>(Arrays.asList(PROPERTY_NAME));
    }
    
    @Override
    public boolean arePartitionsFixed() {
        return false;
    }

    @Override
    public boolean isPropertyPredefined(int stepIdentifier, int partitionIdentifier, String propertyName) {
        return super.isPropertyPredefined(stepIdentifier, partitionIdentifier, propertyName) || predefinedProperties.contains(propertyName);
    }
}
