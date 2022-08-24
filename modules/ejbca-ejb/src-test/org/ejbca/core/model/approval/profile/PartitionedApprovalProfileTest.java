/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.LinkedHashMap;
import java.util.List;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleInformation;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for the PartitionedApprovalProfile class.
 *
 */
public class PartitionedApprovalProfileTest {

    /**
     * Approval is required if there are any partitions that the ANYBODY pseudo-role doesn't have access to
     */
    @Test
    public void testCanApprovalExecute() throws ApprovalException, AuthenticationFailedException {
        //Create a profile with two steps, two partitions in each. 
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            approvalProfile.addPartition(approvalStep.getStepIdentifier());
        }
        List<Approval> approvals = new ArrayList<>();
        for (ApprovalStep step : approvalProfile.getSteps().values()) {
            for (ApprovalPartition partition : step.getPartitions().values()) {
                approvals.add(new Approval("", step.getStepIdentifier(), partition.getPartitionIdentifier()));
            }
        }
        assertFalse("No approvals submitted, check should have failed.", approvalProfile.canApprovalExecute(new ArrayList<Approval>()));
        assertFalse("Incorrect approvals submitted, check should have failed.",
                approvalProfile.canApprovalExecute(Arrays.asList(approvals.get(0), approvals.get(0), approvals.get(0), approvals.get(0))));
        assertTrue("Correct set of approvals submitted, check should have passed.", approvalProfile.canApprovalExecute(approvals));

    }
    
    @Test
    @SuppressWarnings("deprecation")
    public void testCanApproveSuccess() throws PropertyValidationException {
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        List<Role> rolesTokenIsMemberOf = new ArrayList<Role>();
        // The role role1 will be allowed to approve the partition
        Role role1 = new Role(null, "Rolename1");
        Role role2 = new Role(null, "Rolename2");
        role1.setRoleId(1);
        role2.setRoleId(2);
        rolesTokenIsMemberOf.add(role1);
        rolesTokenIsMemberOf.add(role2);
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            ApprovalPartition partition = approvalProfile.addPartition(approvalStep.getStepIdentifier());
            List<RoleInformation> roleInfos = new ArrayList<>();
            RoleInformation roleInfo1 = new RoleInformation(1, "Rolename1", null);
            roleInfos.add(roleInfo1);
            roleInfos.add(new RoleInformation(3, "Rolename3", null));
            DynamicUiProperty<RoleInformation> approvalRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, 
                    roleInfo1, roleInfos);
            //Will make this property into a multi-select instead of single select.
            approvalRoles.setHasMultipleValues(true);
            approvalRoles.setValues(roleInfos);
            partition.addProperty(approvalRoles);
            assertTrue("Correct roles supplied to the method, should have been possible to approve", approvalProfile.canApprove(rolesTokenIsMemberOf, partition));
        }
    }
    
    @Test
    @SuppressWarnings("deprecation")
    public void testCanApproveFail() throws PropertyValidationException {
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        List<Role> rolesTokenIsMemberOf = new ArrayList<Role>();
        Role role1 = new Role(null, "Rolename1");
        Role role2 = new Role(null, "Rolename2");
        role1.setRoleId(1);
        role2.setRoleId(2);
        rolesTokenIsMemberOf.add(role1);
        rolesTokenIsMemberOf.add(role2);
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            ApprovalPartition partition = approvalProfile.addPartition(approvalStep.getStepIdentifier());
            List<RoleInformation> roleInfos = new ArrayList<>();
            RoleInformation roleInfo3 = new RoleInformation(3, "Rolename3", null);
            roleInfos.add(roleInfo3);
            roleInfos.add(new RoleInformation(4, "Rolename4", null));
            DynamicUiProperty<RoleInformation> approvalRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, 
                    roleInfo3, roleInfos);
            //Will make this property into a multi-select instead of single select.
            approvalRoles.setHasMultipleValues(true);
            approvalRoles.setValues(roleInfos);
            partition.addProperty(approvalRoles);
            assertFalse("Wrong roles supplied to the method, should have been impossible to approve", approvalProfile.canApprove(rolesTokenIsMemberOf, partition));
        }
    }

    @Test
    @SuppressWarnings("deprecation")
    public void testCanViewSuccess() throws PropertyValidationException {
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        List<Role> rolesTokenIsMemberOf = new ArrayList<Role>();
        // This role will be allowed to view the partition
        Role role1 = new Role(null, "Rolename1");
        Role role2 = new Role(null, "Rolename2");
        role1.setRoleId(1);
        role2.setRoleId(2);
        rolesTokenIsMemberOf.add(role1);
        rolesTokenIsMemberOf.add(role2);
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            ApprovalPartition partition = approvalProfile.addPartition(approvalStep.getStepIdentifier());
            List<RoleInformation> roleInfos = new ArrayList<>();
            RoleInformation roleInfo1 = new RoleInformation(1, "Rolename1", null);
            roleInfos.add(roleInfo1);
            roleInfos.add(new RoleInformation(3, "Rolename3", null));
            DynamicUiProperty<RoleInformation> viewRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_VIEW_RIGHTS, 
                    roleInfo1, roleInfos);
            //Will make this property into a multi-select instead of single select.
            viewRoles.setHasMultipleValues(true);
            viewRoles.setValues(roleInfos);
            partition.addProperty(viewRoles);
            assertTrue("Correct roles supplied to the method, should have been possible to view", approvalProfile.canView(rolesTokenIsMemberOf, partition));
        }
    }
    
    @Test
    @SuppressWarnings("deprecation")
    public void testCanViewSuccessWithoutViewRights() throws PropertyValidationException {
        //Create a profile with two steps, two partitions in each. 
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        List<Role> rolesTokenIsMemberOf = new ArrayList<Role>();
        Role role1 = new Role(null, "Rolename1");
        Role role2 = new Role(null, "Rolename2");
        role1.setRoleId(1);
        role2.setRoleId(2);
        rolesTokenIsMemberOf.add(role1);
        rolesTokenIsMemberOf.add(role2);
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            ApprovalPartition partition = approvalProfile.addPartition(approvalStep.getStepIdentifier());
            List<RoleInformation> roleInfos = new ArrayList<>();
            RoleInformation roleInfo3 = new RoleInformation(1, "Rolename1", null);
            roleInfos.add(roleInfo3);
            roleInfos.add(new RoleInformation(4, "Rolename4", null));
            DynamicUiProperty<RoleInformation> approvalRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, 
                    roleInfo3, roleInfos);
            approvalRoles.setHasMultipleValues(true);
            approvalRoles.setValues(roleInfos);
            partition.addProperty(approvalRoles);
            List<RoleInformation> roleInfos2 = new ArrayList<>();
            roleInfos2.add(new RoleInformation(5, "Rolename5", null));
            DynamicUiProperty<RoleInformation> viewRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_VIEW_RIGHTS, 
                    roleInfo3, roleInfos);
            viewRoles.setHasMultipleValues(true);
            viewRoles.setValues(roleInfos);
            partition.addProperty(viewRoles);
            assertTrue("Correct roles supplied to the method, should have been possible to view", approvalProfile.canView(rolesTokenIsMemberOf, partition));
        }
    }
    
    @Test
    @SuppressWarnings("deprecation")
    public void testCanViewFail() throws PropertyValidationException {
        //Create a profile with two steps, two partitions in each. 
        PartitionedApprovalProfile approvalProfile = new PartitionedApprovalProfile("PartitionedApprovalProfile");
        approvalProfile.initialize();
        //Create another step (one is default)
        approvalProfile.addStepFirst();
        List<Role> rolesTokenIsMemberOf = new ArrayList<Role>();
        Role role1 = new Role(null, "Rolename1");
        Role role2 = new Role(null, "Rolename2");
        role1.setRoleId(1);
        role2.setRoleId(2);
        rolesTokenIsMemberOf.add(role1);
        rolesTokenIsMemberOf.add(role2);
        for (ApprovalStep approvalStep : approvalProfile.getSteps().values()) {
            ApprovalPartition partition = approvalProfile.addPartition(approvalStep.getStepIdentifier());
            List<RoleInformation> roleInfos = new ArrayList<>();
            RoleInformation roleInfo3 = new RoleInformation(3, "Rolename3", null);
            roleInfos.add(roleInfo3);
            roleInfos.add(new RoleInformation(4, "Rolename4", null));
            DynamicUiProperty<RoleInformation> viewRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_VIEW_RIGHTS, 
                    roleInfo3, roleInfos);
            viewRoles.setHasMultipleValues(true);
            viewRoles.setValues(roleInfos);
            partition.addProperty(viewRoles);
            DynamicUiProperty<RoleInformation> approvalRoles = new DynamicUiProperty<RoleInformation>(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS, 
                    roleInfo3, roleInfos);
            approvalRoles.setHasMultipleValues(true);
            approvalRoles.setValues(roleInfos);
            partition.addProperty(approvalRoles);
            assertFalse("Wrong roles supplied to the method, should have been impossible to view", approvalProfile.canView(rolesTokenIsMemberOf, partition));
        }
    }

}
