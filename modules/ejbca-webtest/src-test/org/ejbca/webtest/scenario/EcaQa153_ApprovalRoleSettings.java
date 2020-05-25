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
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AdminRolesHelper;
import org.ejbca.webtest.helper.ApprovalProfilesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Partitioned Approval role settings.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-153">ECAQA-153</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa153_ApprovalRoleSettings extends WebTestBase {

    // Helpers
    private static AdminRolesHelper adminRolesHelper;
    private static ApprovalProfilesHelper approvalProfilesHelper;

    // Test Data
    public static class TestData {
        static final String ROLE_NAME = "ECAQA153_TestRole";
        static final String ROLE_TEMPLATE = "Super Administrators";
        static final String MATCH_WITH = "X509: CN, Common name";
        static final String MATCH_VALUE = "SuperAdmin";
        static final String APPROVAL_PROFILE_NAME = "ECAQA153_Partitioned_Profile";
        static final String APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL = "Partitioned Approval";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        adminRolesHelper = new AdminRolesHelper(webDriver);
        approvalProfilesHelper = new ApprovalProfilesHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() {
        // Remove Administrator Role
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        // Remove Approval Profile
        removeApprovalProfileByName(TestData.APPROVAL_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_createRole() {
        // Add Role
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE);
        adminRolesHelper.saveAccessRule();
    }
    
    @Test
    public void stepB_addApprovalProfile() {
        approvalProfilesHelper.openPage(getAdminWebUrl());
        approvalProfilesHelper.addApprovalProfile((TestData.APPROVAL_PROFILE_NAME));
        approvalProfilesHelper.openEditApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.setApprovalProfileType(TestData.APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL);
        approvalProfilesHelper.setApprovalStepPartitionApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.setApprovalStepPartitionViewPartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.saveApprovalProfile();
        // Verify roles selection
        approvalProfilesHelper.openViewApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasViewPartitionRole(0, 0, TestData.ROLE_NAME);
    }
    
    @Test
    public void stepC_addRoleMember() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.openEditMembersPage(TestData.ROLE_NAME);
        adminRolesHelper.selectMatchWith(TestData.MATCH_WITH);
        adminRolesHelper.selectCa(getCaName());
        adminRolesHelper.setMatchValue(TestData.MATCH_VALUE);
        adminRolesHelper.clickAddMember();
        adminRolesHelper.assertMemberMatchWithRowExists(TestData.MATCH_WITH);
        // Verify roles selection
        approvalProfilesHelper.openPage(getAdminWebUrl());
        approvalProfilesHelper.openViewApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasViewPartitionRole(0, 0, TestData.ROLE_NAME);
    }

}