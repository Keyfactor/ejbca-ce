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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
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
        private static final String ROLE_TEMPLATE = "Super Administrators";
        private static final String MATCH_WITH = "X509: CN, Common name";
        private static final String MATCH_VALUE = "SuperAdmin";
        private static final String APPROVAL_PROFILE_NAME = "ECAQA153_Approval Profile";
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
    public static void exit() throws AuthorizationDeniedException {
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
        // TODO Refactor ECA-7356
        approvalProfilesHelper.addApprovalProfile(getAdminWebUrl(), TestData.APPROVAL_PROFILE_NAME, TestData.ROLE_NAME);
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
        // TODO Refactor ECA-7356
        approvalProfilesHelper.verifyApprovalsViewMode(getAdminWebUrl(), TestData.APPROVAL_PROFILE_NAME, TestData.ROLE_NAME);
    }
    

}