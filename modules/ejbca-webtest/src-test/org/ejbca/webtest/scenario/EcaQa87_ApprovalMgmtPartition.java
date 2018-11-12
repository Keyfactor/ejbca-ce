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
 * @version $Id: EcaQa87_ApprovalMgmtPartition.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
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
        private static final String ROLE_NAME = "ECAQA87_AdminRole1";
        private static final String ROLE_NAME2 = "ECAQA87_AdminRole2";
        private static final String ROLE_TEMPLATE = "Super Administrators";
        private static final String APPROVAL_PROFILE_NAME = "ECAQA87_Partitioned Profile";
        private static final String CA_NAME = "ECAQA87_ApprovalCA";
        private static final String CA_VALIDITY = "1y";
        private static final String CERTIFICATE_PROFILE_NAME = "ECAQA87_ApprovalCertificateProfile";
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
        // TODO Refactor ECA-7356
        approvalProfilesHelper.addApprovalProfile(getAdminWebUrl(), TestData.APPROVAL_PROFILE_NAME, TestData.ROLE_NAME, TestData.ROLE_NAME2);
    }

    @Test
    public void stepC_addStep() {
        // TODO Refactor ECA-7356
        // Add a new step
        approvalProfilesHelper.addStep(TestData.ROLE_NAME, TestData.ROLE_NAME2);
    }

    @Test
    public void stepD_addPartition() {
        // TODO Refactor ECA-7356
        approvalProfilesHelper.addPartition(TestData.ROLE_NAME, TestData.ROLE_NAME2);
    }

    @Test
    public void stepE_addFields() {
        // TODO Refactor ECA-7356
        approvalProfilesHelper.addField();
    }

    @Test
    public void stepF_addNamesAndAdmins() {
        // TODO Refactor ECA-7356
        approvalProfilesHelper.addNamesAndAdmins(TestData.ROLE_NAME, TestData.ROLE_NAME2);
    }

    @Test
    public void stepG_saveAndVerify() {
        // TODO Refactor ECA-7356
        approvalProfilesHelper.saveAndVerify(TestData.ROLE_NAME, TestData.ROLE_NAME2);
    }

    @Test
    public void stepH_createCa() {
        // Add CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        // TODO Refactor ECA-7343
        caHelper.selectApprovalProfileName(TestData.APPROVAL_PROFILE_NAME);
        caHelper.saveCa();
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
