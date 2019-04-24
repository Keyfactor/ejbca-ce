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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;


/**
 * This test verifies that RA administrator is able to review and modify requests, and the privileges are upheld doing this.
 *
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-98">ECAQA-98</a>
 *
 * This test scenario uses 3 different administrators. In order to run it, Firefox profiles with certificates and corresponding names for:
 *
 * profile.firefox.default      (SuperAdmin)
 * profile.firefox.raadmin      (SeleniumRaAdmin)
 * profile.firefox.raadminalt   (SeleniumRaAdmin1)
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa98_EditApprovals extends WebTestBase {

    private static int approveRequestId = -1;

    // Helpers
    private static AddEndEntityHelper addEndEntityHelperDefault;
    private static AdminRolesHelper adminRolesHelperDefault;
    private static ApprovalProfilesHelper approvalProfilesHelperDefault;
    private static CaHelper caHelperDefault;
    private static RaWebHelper raWebHelperDefault;
    private static RaWebHelper raWebHelperRaAdmin;
    private static RaWebHelper raWebHelperRaAdmin1;

    // Test Data
    public static class TestData {
        static final String APPROVAL_PROFILE_NAME = "ECAQA98AP";
        static final String CA_NAME = "ECAQA98TestCA";
        static final String END_ENTITY_PROFILE = "EMPTY";
        static final String END_ENTITY_NAME = "EcaQa98EE" + new Random().nextInt();
        static final String END_ENTITY_NAME_MODIFIED = END_ENTITY_NAME + "_Modified";
        static final String END_ENTITY_PASSWORD = "foo123";
        static final String RA_PENDING_APPROVAL_TYPE = "Add End Entity";
        static final String RA_PENDING_APPROVAL_STATUS = "Waiting for Approval";

        static final Map<String,String> INPUT_END_ENTITY_FIELDMAP = new HashMap<>();
        static {
            INPUT_END_ENTITY_FIELDMAP.put("Username", END_ENTITY_NAME);
            INPUT_END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", END_ENTITY_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("Confirm Password", END_ENTITY_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("CN, Common name", END_ENTITY_NAME);
        }
        static final String APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL = "Partitioned Approval";
        static final String ROLE_TEMPLATE = "RA Administrators";
        static final String USER_NAME = "SeleniumRaAdmin";
        static final String USER_NAME1 = "SeleniumRaAdmin1";
        static final String ROLE_NAME = "SeleniumRaAdminRoleECAQA98";
        static final String MATCH_WITH = "X509: CN, Common name";
        static final String APPROVE_MESSAGE_CANNOT_EDIT = "You have edited this request and cannot approve it";
        static final String APPROVE_MESSAGE_APPROVED_AND_EXECUTED = "This request has been approved and executed already";
    }

    @BeforeClass
    public static void init() {
        // Default
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_DEFAULT);
        final WebDriver webDriverDefault = getLastWebDriver();
        addEndEntityHelperDefault = new AddEndEntityHelper(webDriverDefault);
        adminRolesHelperDefault = new AdminRolesHelper(webDriverDefault);
        approvalProfilesHelperDefault = new ApprovalProfilesHelper(webDriverDefault);
        caHelperDefault = new CaHelper(webDriverDefault);
        raWebHelperDefault = new RaWebHelper(webDriverDefault);
        // SeleniumRaAdmin
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_RAADMIN);
        final WebDriver webDriverRaAdmin = getLastWebDriver();
        raWebHelperRaAdmin = new RaWebHelper(webDriverRaAdmin);
        // SeleniumRaAdmin1
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_RAADMINALT);
        final WebDriver webDriverRaAdmin1 = getLastWebDriver();
        raWebHelperRaAdmin1 = new RaWebHelper(webDriverRaAdmin1);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove CA
        removeCaByName(TestData.CA_NAME);
        // Remove Approval Request
        removeApprovalRequestByRequestId(approveRequestId);
        // Remove Administrator Role
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        // Remove Approval Profile
        removeApprovalProfileByName(TestData.APPROVAL_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_setupPrerequisites() {
        // Add role using 'RA Administrators' template
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.addRole(TestData.ROLE_NAME);
        adminRolesHelperDefault.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.selectRoleTemplate(TestData.ROLE_TEMPLATE);
        adminRolesHelperDefault.saveAccessRule();
        // Add access rules
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.switchViewModeFromBasicToAdvanced();
        adminRolesHelperDefault.setRuleCheckedRadioButton("/ca/", "ALLOW");
        adminRolesHelperDefault.setRuleCheckedRadioButton("/endentityprofilesrules/", "ALLOW");
        adminRolesHelperDefault.saveAccessRule();
        // Add member SeleniumRaAdmin
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.openEditMembersPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.selectMatchWith(TestData.MATCH_WITH);
        adminRolesHelperDefault.selectCa(getCaName());
        adminRolesHelperDefault.setMatchValue(TestData.USER_NAME);
        adminRolesHelperDefault.clickAddMember();
        // Add memeber SeleniumRaAdmin1
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.openEditMembersPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.selectMatchWith(TestData.MATCH_WITH);
        adminRolesHelperDefault.selectCa(getCaName());
        adminRolesHelperDefault.setMatchValue(TestData.USER_NAME1);
        adminRolesHelperDefault.clickAddMember();
        // Create Approval Profile
        approvalProfilesHelperDefault.openPage(getAdminWebUrl());
        approvalProfilesHelperDefault.addApprovalProfile(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelperDefault.openEditApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelperDefault.setApprovalProfileType(TestData.APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL);
        approvalProfilesHelperDefault.setApprovalStepPartitionApprovePartitionRole(0, 0, TestData.ROLE_NAME);
        approvalProfilesHelperDefault.saveApprovalProfile();
        // Create CA
        caHelperDefault.openPage(getAdminWebUrl());
        caHelperDefault.addCa(TestData.CA_NAME);
        caHelperDefault.setValidity("1y");
        caHelperDefault.selectAllApprovalProfileNames(TestData.APPROVAL_PROFILE_NAME);
        caHelperDefault.createCa();
    }

    @Test
    public void stepB_enrollEndEntity() {
        addEndEntityHelperDefault.openPage(getAdminWebUrl());
        addEndEntityHelperDefault.setEndEntityProfile(TestData.END_ENTITY_PROFILE);
        addEndEntityHelperDefault.setCa(TestData.CA_NAME);
        addEndEntityHelperDefault.fillFields(TestData.INPUT_END_ENTITY_FIELDMAP);
        addEndEntityHelperDefault.addEndEntity();
        addEndEntityHelperDefault.assertEndEntityAlertMessageDisplayed();
    }

    @Test
    public void stepC_findPending() {
        raWebHelperDefault.openPage(getRaWebUrl());
        raWebHelperDefault.clickMenuManageRequests();
        raWebHelperDefault.clickTabPendingRequests();
        // Get rows of pending approval request
        final List<WebElement> pendingApprovalRequestRow = raWebHelperDefault.getRequestsTableRow(TestData.CA_NAME, TestData.RA_PENDING_APPROVAL_TYPE, TestData.END_ENTITY_NAME, TestData.RA_PENDING_APPROVAL_STATUS);
        raWebHelperDefault.assertHasRequestRow(pendingApprovalRequestRow);
        approveRequestId = raWebHelperDefault.getRequestIdFromRequestRow(pendingApprovalRequestRow);
    }

    @Test
    public void stepD_editRequest() {
        raWebHelperRaAdmin.openPage(getRaWebUrl());
        raWebHelperRaAdmin.clickMenuManageRequests();
        raWebHelperRaAdmin.clickTabApproveRequests();
        // Get rows
        final List<WebElement> approveRequestRow = raWebHelperRaAdmin.getRequestsTableRow(TestData.CA_NAME, TestData.RA_PENDING_APPROVAL_TYPE, TestData.END_ENTITY_NAME, TestData.RA_PENDING_APPROVAL_STATUS);
        raWebHelperRaAdmin.assertHasRequestRow(approveRequestRow);
        raWebHelperRaAdmin.triggerRequestReviewLinkFromRequestRow(approveRequestRow);
        raWebHelperRaAdmin.assertRequestApproveButtonExists();
        raWebHelperRaAdmin.assertRequestRejectButtonExists();
        raWebHelperRaAdmin.triggerRequestEditLink();
        raWebHelperRaAdmin.fillManageRequestEditCommonName(TestData.END_ENTITY_NAME_MODIFIED);
        raWebHelperRaAdmin.triggerRequestEditSaveForm();
        raWebHelperRaAdmin.assertSubjectDistinguishedNameHasText("CN=" + TestData.END_ENTITY_NAME_MODIFIED);
        raWebHelperRaAdmin.assertApproveMessageHasText(TestData.APPROVE_MESSAGE_CANNOT_EDIT);
        raWebHelperRaAdmin.assertRequestApproveButtonDoesNotExist();
        raWebHelperRaAdmin.assertRequestRejectButtonDoesNotExist();
    }

    @Test
    public void stepE_approvePostEdit() {
        raWebHelperRaAdmin1.openPage(getRaWebUrl());
        raWebHelperRaAdmin1.clickMenuManageRequests();
        raWebHelperRaAdmin1.clickTabApproveRequests();
        // Get rows
        final List<WebElement> approveRequestRow = raWebHelperRaAdmin1.getRequestsTableRow(TestData.CA_NAME, TestData.RA_PENDING_APPROVAL_TYPE, TestData.END_ENTITY_NAME_MODIFIED, TestData.RA_PENDING_APPROVAL_STATUS);
        raWebHelperRaAdmin1.assertHasRequestRow(approveRequestRow);
        raWebHelperRaAdmin1.triggerRequestReviewLinkFromRequestRow(approveRequestRow);
        raWebHelperRaAdmin1.assertRequestApproveButtonExists();
        raWebHelperRaAdmin1.assertRequestRejectButtonExists();
        raWebHelperRaAdmin1.triggerRequestApproveButton();
        raWebHelperRaAdmin1.assertSubjectDistinguishedNameHasText("CN=" + TestData.END_ENTITY_NAME_MODIFIED);
        raWebHelperRaAdmin1.assertApproveMessageHasText(TestData.APPROVE_MESSAGE_APPROVED_AND_EXECUTED);
    }
}