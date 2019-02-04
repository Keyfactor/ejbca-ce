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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AdminRolesHelper;
import org.ejbca.webtest.helper.ApprovalProfilesHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper.ApprovalSetting;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Arrays;
import java.util.List;

/**
 * This test belongs to a series of tests:
 * <ul>
 *     <li>ECAQA-87</li>
 *     <li>ECAQA-88</li>
 *     <li>ECAQA-89</li>
 * </ul>
 * Verify if operations responsible for configuring Certificate Profiles and Certificate Authorities work as expected.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-87">ECAQA-87</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa87_ApprovalMgmtPartition extends WebTestBase {

    // Helpers
    private static AdminRolesHelper adminRolesHelper;
    private static ApprovalProfilesHelper approvalProfilesHelper;
    private static CaHelper caHelper;
    private static CertificateProfileHelper certificateProfileHelper;

    // Test Data
    public static class TestData {
        static final String ROLE_ANYBODY = "Anybody";
        static final String ROLE_NAME = "ECAQA87_AdminRole1";
        static final String ROLE_NAME2 = "ECAQA87_AdminRole2";
        static final List<String> ROLE_NAMES = Arrays.asList(ROLE_NAME, ROLE_NAME2);
        static final List<String> ROLE_NAMES_ALL = Arrays.asList(ROLE_ANYBODY, ROLE_NAME, ROLE_NAME2);
        static final String ROLE_TEMPLATE = "Super Administrators";
        static final String APPROVAL_PROFILE_NAME = "ECAQA87_Partitioned Profile";
        static final String APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL = "Partitioned Approval";
        static final String APPROVAL_PROFILE_REQUEST_EXPIRATION_PERIOD = "7h 43m 20s";
        static final String APPROVAL_PROFILE_APPROVAL_EXPIRATION_PERIOD = "8h 16m 40s";
        static final String APPROVAL_PROFILE_STEP_0_PARTITION_NAME_0 = "1:A";
        static final String APPROVAL_PROFILE_STEP_0_PARTITION_NAME_1 = "1:B";
        static final String APPROVAL_PROFILE_STEP_1_PARTITION_NAME_0 = "2:A";
        static final String CA_NAME = "ECAQA87_ApprovalCA";
        static final String CA_VALIDITY = "1y";
        static final String CERTIFICATE_PROFILE_NAME = "ECAQA87_ApprovalCertificateProfile";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        adminRolesHelper = new AdminRolesHelper(webDriver);
        approvalProfilesHelper = new ApprovalProfilesHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove Administrator Roles
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        removeAdministratorRoleByName(TestData.ROLE_NAME2);
        // Remove CA
        removeCaByName(TestData.CA_NAME);
        // Remove Certificate Profile
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        // Remove Approval Profile
        removeApprovalProfileByName(TestData.APPROVAL_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_createRoles() {
        // Add Role 1
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE);
        adminRolesHelper.saveAccessRule();
        // Add Role 2
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME2);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME2);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE);
        adminRolesHelper.saveAccessRule();
    }

    @Test
    public void stepB_addApprovalProfile() {
        approvalProfilesHelper.openPage(getAdminWebUrl());
        approvalProfilesHelper.addApprovalProfile(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.openEditApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.setApprovalProfileType(TestData.APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL);
        approvalProfilesHelper.setRequestExpirationPeriod(TestData.APPROVAL_PROFILE_REQUEST_EXPIRATION_PERIOD);
        approvalProfilesHelper.setApprovalExpirationPeriod(TestData.APPROVAL_PROFILE_APPROVAL_EXPIRATION_PERIOD);
        approvalProfilesHelper.assertAddStepButtonPresent();
        approvalProfilesHelper.assertFormsSaveAndCancelButtonsPresent();
        approvalProfilesHelper.assertApprovalSteps(1, TestData.ROLE_NAMES_ALL);
    }

    @Test
    public void stepC_addStep() {
        approvalProfilesHelper.addStep(2, TestData.ROLE_NAMES);
    }

    @Test
    public void stepD_addPartition() {
        approvalProfilesHelper.addPartition(0, 2, TestData.ROLE_NAMES);
    }

    @Test
    public void stepE_addFields() {
        approvalProfilesHelper.addField(0, 0, "Check Box");
        approvalProfilesHelper.addField(0, 1, "Radio Button");
        approvalProfilesHelper.addFieldRadioButtonLabel(0, 1, "Label1");
        approvalProfilesHelper.addFieldRadioButtonLabel(0, 1, "Label2");
        approvalProfilesHelper.addField(1, 0, "Number (Short)");
        //
        approvalProfilesHelper.assertApprovalStepPartitionFieldTypeExists(0, 0, "Check Box", 1);
        approvalProfilesHelper.assertApprovalStepPartitionFieldTypeExists(0, 1, "Radio Button", 2);
        approvalProfilesHelper.assertApprovalStepPartitionFieldTypeExists(1, 0, "Number (Short)", 1);
    }

    @Test
    public void stepF_addNamesAndAdmins() {
        approvalProfilesHelper.setApprovalStepPartitionName(0, 0, TestData.APPROVAL_PROFILE_STEP_0_PARTITION_NAME_0);
        approvalProfilesHelper.setApprovalStepPartitionName(0, 1, TestData.APPROVAL_PROFILE_STEP_0_PARTITION_NAME_1);
        approvalProfilesHelper.setApprovalStepPartitionName(1, 0, TestData.APPROVAL_PROFILE_STEP_1_PARTITION_NAME_0);
        //
        approvalProfilesHelper.setApprovalStepPartitionApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.setApprovalStepPartitionViewPartitionRole(0, 0, TestData.ROLE_ANYBODY);
        approvalProfilesHelper.setApprovalStepPartitionApprovePartitionRole(0, 1, TestData.ROLE_NAME2);
        approvalProfilesHelper.setApprovalStepPartitionViewPartitionRole(0, 1, TestData.ROLE_ANYBODY);
        approvalProfilesHelper.setApprovalStepPartitionApprovePartitionRole(1, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.setApprovalStepPartitionViewPartitionRole(1, 0, TestData.ROLE_ANYBODY);
    }

    @Test
    public void stepG_saveAndVerify() {
        // Save profile
        approvalProfilesHelper.saveApprovalProfile();
        //
        approvalProfilesHelper.openViewApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelper.assertApprovalProfileTypeSelectedName(TestData.APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL);
        approvalProfilesHelper.assertRequestExpirationPeriodHasValue(TestData.APPROVAL_PROFILE_REQUEST_EXPIRATION_PERIOD);
        approvalProfilesHelper.assertApprovalExpirationPeriodHasValue(TestData.APPROVAL_PROFILE_APPROVAL_EXPIRATION_PERIOD);
        approvalProfilesHelper.assertBackButtonPresent();
        // Assert form elements are disabled
        approvalProfilesHelper.assertApprovalProfileTypeIsEnabled(false);
        approvalProfilesHelper.assertRequestExpirationPeriodIsEnabled(false);
        approvalProfilesHelper.assertApprovalExpirationPeriodIsEnabled(false);
        approvalProfilesHelper.assertMaxExtensionTimeIsEnabled(false);
        approvalProfilesHelper.assertAllowSelfApprovedRequestEditingIsEnabled(false);
        approvalProfilesHelper.assertApprovalStepPartitionNameIsEnabled(0, 0, false);
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRoleIsEnabled(0, 0, false);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRoleIsEnabled(0, 0, false);
        approvalProfilesHelper.assertApprovalStepPartitionNameIsEnabled(0, 1, false);
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRoleIsEnabled(0, 1, false);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRoleIsEnabled(0, 1, false);
        approvalProfilesHelper.assertApprovalStepPartitionNameIsEnabled(1, 0, false);
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRoleIsEnabled(1, 0, false);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRoleIsEnabled(1, 0, false);
        // Assert names of partitions
        approvalProfilesHelper.assertApprovalStepPartitionNameHasValue(0, 0, TestData.APPROVAL_PROFILE_STEP_0_PARTITION_NAME_0);
        approvalProfilesHelper.assertApprovalStepPartitionNameHasValue(0, 1, TestData.APPROVAL_PROFILE_STEP_0_PARTITION_NAME_1);
        approvalProfilesHelper.assertApprovalStepPartitionNameHasValue(1, 0, TestData.APPROVAL_PROFILE_STEP_1_PARTITION_NAME_0);
        // Assert Step 1 Partition 1 has roles
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(0, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasViewPartitionRole(0, 0, TestData.ROLE_ANYBODY);
        // Assert Step 1 Partition 2 has roles
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(0, 1, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasApprovePartitionRole(0, 1, TestData.ROLE_NAME2);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(0, 1, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasViewPartitionRole(0, 1, TestData.ROLE_ANYBODY);
        // Assert Step 2 Partition 1 has roles
        approvalProfilesHelper.assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(1, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasApprovePartitionRole(1, 0, TestData.ROLE_NAME);
        approvalProfilesHelper.assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(1, 0, 1);
        approvalProfilesHelper.assertApprovalStepPartitionHasViewPartitionRole(1, 0, TestData.ROLE_ANYBODY);
    }

    @Test
    public void stepH_createCa() {
        // Add CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.selectAllApprovalProfileNames(TestData.APPROVAL_PROFILE_NAME);
        caHelper.createCa();
    }

    @Test
    public void stepI_createCp() {
        // Create Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        // Edit Certificate Profile
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Set Approval Settings
        certificateProfileHelper.selectApprovalSetting(ApprovalSetting.ADD_OR_EDIT_END_ENTITY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.selectApprovalSetting(ApprovalSetting.KEY_RECOVERY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.selectApprovalSetting(ApprovalSetting.REVOCATION, TestData.APPROVAL_PROFILE_NAME);
        // Save the changes
        certificateProfileHelper.saveCertificateProfile();
        // Verify View mode
        certificateProfileHelper.assertCertificateProfileNameExists(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openViewCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Check Approval Settings selection
        certificateProfileHelper.assertApprovalSettingHasSelectedName(ApprovalSetting.ADD_OR_EDIT_END_ENTITY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.assertApprovalSettingHasSelectedName(ApprovalSetting.KEY_RECOVERY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.assertApprovalSettingHasSelectedName(ApprovalSetting.REVOCATION, TestData.APPROVAL_PROFILE_NAME);
    }

}
