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

package org.ejbca.webtest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * 
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa153_ApprovalRoleSettings extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
    private static final String roleName = "Test_Role";
    private static final String approvalProfileName = "Test_approval_profile";
    
    private static WebDriver webDriver;
    private static RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);
    
    
    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        Role role = roleSession.getRole(admin, null, roleName);
        roleSession.deleteRoleIdempotent(admin, role.getRoleId());
        Map<Integer, String> approvalIdNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (Entry<Integer, String> approvalProfile : approvalIdNameMap.entrySet()) {
            if (approvalProfile.getValue().equals(approvalProfileName)) {
                approvalProfileSession.removeApprovalProfile(admin, approvalProfile.getKey());
            }
        }
        webDriver.quit();
    }

    
    @Test
    public void testA_createRole() throws AuthorizationDeniedException {
        webDriver.get(getAdminWebUrl());
        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
        adminRolesLink.click();
        webDriver.findElement(By.id("roles:list:addRoleButton")).click();;
        webDriver.findElement(By.id("modal:roleNameInputField")).sendKeys(roleName);
        webDriver.findElement(By.id("modal:confirmAddRoleButton")).click();
        
        WebElement infoMessage = webDriver.findElement(By.xpath("//li[@class='infoMessage']"));
        assertEquals("Unexpected info message while adding role","Role added." , infoMessage.getText());
        
        int roleId = roleSession.getRole(admin, null, roleName).getRoleId();
        String findRoleTableRow = "//a[@href='accessrules.xhtml?roleId=" + roleId + "']";
        webDriver.findElement(By.xpath(findRoleTableRow)).click();
        
        Select roleTemplate = new Select(webDriver.findElement(By.id("accessRulesForm:selectrole")));
        roleTemplate.selectByValue("SUPERADMINISTRATOR");
        webDriver.findElement(By.xpath("//input[@value='Save']")).click();
    }
    
    @Test
    public void testB_addApprovalProfile() {
        webDriver.get(getAdminWebUrl());
        WebElement approvalProfilesLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.jsf')]"));
        approvalProfilesLink.click();
        // Dynamically rendered items require some special handling...
        WebElement inputName = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@type='text']]"));
        inputName.sendKeys(approvalProfileName);
        WebElement addProfile = webDriver.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@value='Add']]"));
        addProfile.sendKeys(Keys.RETURN);
        
        WebElement addedItemRow = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), 'Test_approval_profile')]"));
        WebElement addedItemEditButton = addedItemRow.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='Edit']"));
        addedItemEditButton.sendKeys(Keys.RETURN);
        
        Select dropDownProfileType =  new Select(webDriver.findElement(By.id("approvalProfilesForm:selectOneMenuApprovalType")));
        dropDownProfileType.selectByValue("PARTITIONED_APPROVAL");
        List<WebElement> stepAdmins = webDriver.findElements(By.xpath("//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        for (WebElement box : stepAdmins) {
            Select selectAdmin = new Select(box);
            selectAdmin.deselectAll();
            selectAdmin.selectByVisibleText(roleName);
        }
        WebElement saveButton =  webDriver.findElement(By.xpath("//td[@class='editColumn2']/span/input[contains(@name,'approvalProfilesForm:j_id') and //input[@value='Save']]"));
        saveButton.sendKeys(Keys.RETURN);
        
        verifyApprovalsViewMode();
    }
    
    @Test
    public void testC_addRoleMember() throws AuthorizationDeniedException {
        webDriver.get(getAdminWebUrl());
        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
        adminRolesLink.click();
        
        int roleId = roleSession.getRole(admin, null, roleName).getRoleId();
        String findRoleTableRow = "//a[@href='rolemembers.xhtml?roleId=" + roleId + "']";
        webDriver.findElement(By.xpath(findRoleTableRow)).click();
        
        Select matchWith = new Select(webDriver.findElement(By.id("rolemembers:list:matchWith")));
        matchWith.selectByVisibleText("X509: CN, Common name");
        Select selectCa = new Select(webDriver.findElement(By.id("rolemembers:list:caId")));
        selectCa.selectByVisibleText(getCaName());
        WebElement matchValue = webDriver.findElement(By.id("rolemembers:list:tokenMatchValue"));
        matchValue.sendKeys("SuperAdmin");
        webDriver.findElement(By.xpath("//input[@value='Add']")).click();
        
        WebElement table = webDriver.findElement(By.id("rolemembers:list"));
        List<WebElement> tableRows = table.findElements(By.xpath("../table/tbody/tr"));
        assertTrue("Unexpected number of role members", tableRows.size() == 1);
        
        verifyApprovalsViewMode();
    }
    
    private void verifyApprovalsViewMode() {
        webDriver.get(getAdminWebUrl());
        WebElement approvalProfilesLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.jsf')]"));
        approvalProfilesLink.click();
        
        WebElement addedItemRowPostEdit = webDriver.findElement(By.xpath("//tbody/tr/td[contains(text(), 'Test_approval_profile')]"));
        WebElement addedItemViewButton = addedItemRowPostEdit.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='View']"));
        addedItemViewButton.sendKeys(Keys.RETURN);
    
        List<WebElement> stepAdminsViewMode = webDriver.findElements(By.xpath("//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        for (WebElement box : stepAdminsViewMode) {
            Select selectAdmin = new Select(box);
            assertEquals("Roles authorized to view and approve partition was not saved / visible in 'View mode'", roleName, selectAdmin.getFirstSelectedOption().getText());
        }
    }
}