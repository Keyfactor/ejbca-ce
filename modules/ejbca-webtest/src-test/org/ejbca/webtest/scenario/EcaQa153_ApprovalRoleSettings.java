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
 * @version $Id: EcaQa153_ApprovalRoleSettings.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
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
//        webDriver.get(getAdminWebUrl());
//        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
//        adminRolesLink.click();
//        webDriver.findElement(By.id("roles:list:addRoleButton")).click();;
//        webDriver.findElement(By.id("modal:roleNameInputField")).sendKeys(roleName);
//        webDriver.findElement(By.id("modal:confirmAddRoleButton")).click();
//        WebElement infoMessage = webDriver.findElement(By.xpath("//li[@class='infoMessage']"));
//        assertEquals("Unexpected info message while adding role","Role added." , infoMessage.getText());
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
//        int roleId = roleSession.getRole(admin, null, roleName).getRoleId();
//        String findRoleTableRow = "//a[@href='accessrules.xhtml?roleId=" + roleId + "']";
//        webDriver.findElement(By.xpath(findRoleTableRow)).click();
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
//        Select roleTemplate = new Select(webDriver.findElement(By.id("accessRulesForm:selectrole")));
//        roleTemplate.selectByValue("SUPERADMINISTRATOR");
//        webDriver.findElement(By.xpath("//input[@value='Save']")).click();
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
//        webDriver.get(getAdminWebUrl());
//        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
//        adminRolesLink.click();
        adminRolesHelper.openPage(getAdminWebUrl());
//        int roleId = roleSession.getRole(admin, null, roleName).getRoleId();
//        String findRoleTableRow = "//a[@href='rolemembers.xhtml?roleId=" + roleId + "']";
//        webDriver.findElement(By.xpath(findRoleTableRow)).click();
        adminRolesHelper.openEditMembersPage(TestData.ROLE_NAME);
//        Select matchWith = new Select(webDriver.findElement(By.id("rolemembers:list:matchWith")));
//        matchWith.selectByVisibleText("X509: CN, Common name");
        adminRolesHelper.selectMatchWith(TestData.MATCH_WITH);
//        Select selectCa = new Select(webDriver.findElement(By.id("rolemembers:list:caId")));
//        selectCa.selectByVisibleText(getCaName());
        adminRolesHelper.selectCa(getCaName());
//        WebElement matchValue = webDriver.findElement(By.id("rolemembers:list:tokenMatchValue"));
//        matchValue.sendKeys("SuperAdmin");
        adminRolesHelper.setMatchValue(TestData.MATCH_VALUE);
//        webDriver.findElement(By.xpath("//input[@value='Add']")).click();
        adminRolesHelper.clickAddMember();
//        WebElement table = webDriver.findElement(By.id("rolemembers:list"));
//        List<WebElement> tableRows = table.findElements(By.xpath("../table/tbody/tr"));
//        assertTrue("Unexpected number of role members", tableRows.size() == 1);
        adminRolesHelper.assertMemberMatchWithRowExists(TestData.MATCH_WITH);
        // TODO Refactor ECA-7356
        approvalProfilesHelper.verifyApprovalsViewMode(getAdminWebUrl(), TestData.APPROVAL_PROFILE_NAME, TestData.ROLE_NAME);
    }
    

}