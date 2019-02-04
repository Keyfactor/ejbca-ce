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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.Keys;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;


/**
 * This tests uses 3 different administrators. In order to run it, Firefox profiles with certificates and corresponding names for:
 *
 * profile.firefox.superadmin
 * profile.firefox.raadmin
 * profile.firefox.raadminalt
 *
 * ...defined in profiles.properties is required. Additionally 2 roles (with the same name as the Firefox profiles superadmin, raadmin and raadminalt)
 * is required, with corresponding members (e.g. certificate serial number used in the profiles).
 *
 * Certificate for 'profile.firefox.superadmin' should be member of the SuperAdministrator role or any other role with root access.
 * Access rule setup for the raadmin and raadminalt is NOT required (it will be setup by the test).
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa98_EditApprovals extends WebTestBase {

    private static WebDriver webDriverSuperAdmin;
    private static WebDriverWait webDriverSuperAdminWait;
    private static WebDriver webDriverAdmin1;
    private static WebDriverWait webDriverAdmin1Wait;
    private static WebDriver webDriverAdmin2;
    private static WebDriverWait webDriverAdmin2Wait;

    private static final String approvalProfileName = "ECAQA98AP";
    private static final String caName = "ECAQA98TestCA";
    private static final String eeName = "EcaQa98EE" + new Random().nextInt();

    private static int requestId = -1;

    // Helpers
    private static CaHelper caHelper = new CaHelper(webDriverSuperAdmin);
    
    private static RoleSessionRemote roleSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class);
    private static ApprovalSessionRemote approvalSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalSessionRemote.class);
    private static ApprovalProfileSessionRemote approvalProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ApprovalProfileSessionRemote.class);

    @BeforeClass
    public static void init() {
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_SUPERADMIN);
        webDriverSuperAdmin = getWebDriver();
        webDriverSuperAdminWait = getWebDriverWait();
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_RAADMIN);
        webDriverAdmin1 = getWebDriver();
        webDriverAdmin1Wait = getWebDriverWait();
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_RAADMINALT);
        webDriverAdmin2 = getWebDriver();
        webDriverAdmin2Wait = getWebDriverWait();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        removeCaByName(caName);
        Map<Integer, String> approvalIdNameMap = approvalProfileSession.getApprovalProfileIdToNameMap();
        for (Entry<Integer, String> approvalProfile : approvalIdNameMap.entrySet()) {
            if (approvalProfile.getValue().equals(approvalProfileName)) {
                approvalProfileSession.removeApprovalProfile(ADMIN_TOKEN, approvalProfile.getKey());
            }
        }
        approvalSession.removeApprovalRequest(ADMIN_TOKEN, requestId);
        if (webDriverAdmin1 != null) {
            webDriverAdmin1.quit();
        }
        if (webDriverAdmin2 != null) {
            webDriverAdmin2.quit();
        }
        if (webDriverSuperAdmin != null) {
            webDriverSuperAdmin.quit();
        }
    }

    @Test
    public void testA_setupPrerequisites() throws AuthorizationDeniedException, RoleExistsException {
        // Create Approval Profile

        webDriverSuperAdmin.get(getAdminWebUrl());
        WebElement approvalProfilesLink = webDriverSuperAdmin.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/approval/editapprovalprofiles.xhtml')]"));
        approvalProfilesLink.click();
        // Dynamically rendered items require some special handling...
        WebElement inputName = webDriverSuperAdmin.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@type='text']]"));
        inputName.sendKeys(approvalProfileName);
        WebElement addProfile = webDriverSuperAdmin.findElement(By.xpath("//input[contains(@name,'editapprovalprofiles:j_id') and //input[@value='Add']]"));
        addProfile.sendKeys(Keys.RETURN);

        WebElement addedItemRow = webDriverSuperAdmin.findElement(By.xpath("//tbody/tr/td[contains(text(), 'ECAQA98AP')]"));
        WebElement addedItemEditButton = addedItemRow.findElement(By.xpath("../td[@class='gridColumn2']/div/input[@value='Edit']"));
        addedItemEditButton.sendKeys(Keys.RETURN);

        Select dropDownProfileType =  new Select(webDriverSuperAdmin.findElement(By.id("approvalProfilesForm:selectOneMenuApprovalType")));
        dropDownProfileType.selectByValue("PARTITIONED_APPROVAL");
        List<WebElement> stepAdmins = webDriverSuperAdmin.findElements(By.xpath("//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:j_id')]"));
        try {
            for (WebElement box : stepAdmins) {
                Select selectAdmin = new Select(box);
                selectAdmin.deselectAll();
                selectAdmin.selectByVisibleText(getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMIN));
                selectAdmin.selectByVisibleText(getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMINALT));
            }
        } catch (NoSuchElementException e) {
            fail("Failed to setup prerequieites.\n" + e.getMessage() + "\n Make sure RA Admin roles has names corresponding to "
                    + "what is set in conf/profiles.proerties");
        }
        WebElement saveButton =  webDriverSuperAdmin.findElement(By.xpath("//td[@class='editColumn2']/span/input[contains(@name,'approvalProfilesForm:j_id') and //input[@value='Save']]"));
        saveButton.sendKeys(Keys.RETURN);

        //Create CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(caName);
        caHelper.setValidity("1y");
        caHelper.selectApprovalProfileName(approvalProfileName);
        caHelper.saveCa();
        
        Role raAdmin1 = roleSession.getRole(ADMIN_TOKEN, getNamespace(), getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMIN));
        Role raAdmin2 = roleSession.getRole(ADMIN_TOKEN, getNamespace(), getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMINALT));
        raAdmin1.getAccessRules().put(StandardRules.CAACCESS.resource(), true);
        raAdmin2.getAccessRules().put(StandardRules.CAACCESS.resource(), true);
        raAdmin1.getAccessRules().put(AccessRulesConstants.ENDENTITYPROFILEPREFIX, true);
        raAdmin2.getAccessRules().put(AccessRulesConstants.ENDENTITYPROFILEPREFIX, true);
        roleSession.persistRole(ADMIN_TOKEN, raAdmin1);
        roleSession.persistRole(ADMIN_TOKEN, raAdmin2);
    }

    @Test
    public void testB_enrollEndEntity() {
        webDriverSuperAdmin.get(getAdminWebUrl());
        WebElement addEeLink = webDriverSuperAdmin.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/ra/addendentity.jsp')]"));
        addEeLink.click();

        Select dropDownEepPreSelect =  new Select(webDriverSuperAdmin.findElement(By.xpath("//select[@name='selectendentityprofile']")));
        dropDownEepPreSelect.selectByVisibleText("EMPTY");
        Select dropDownCaPreSelect =  new Select(webDriverSuperAdmin.findElement(By.xpath("//select[@name='selectca']")));
        dropDownCaPreSelect.selectByVisibleText(caName);
        webDriverSuperAdmin.findElement(By.xpath("//input[@name='textfieldusername']")).sendKeys(eeName);
        webDriverSuperAdmin.findElement(By.xpath("//input[@name='textfieldpassword']")).sendKeys("foo123");
        webDriverSuperAdmin.findElement(By.xpath("//input[@name='textfieldconfirmpassword']")).sendKeys("foo123");
        webDriverSuperAdmin.findElement(By.xpath("//input[@name='textfieldsubjectdn26']")).sendKeys(eeName); //TODO Identifier seems fragile...
        webDriverSuperAdmin.findElement(By.xpath("//input[@name='buttonadduser']")).click();
        WebElement messageInfo = webDriverSuperAdmin.findElement(By.xpath("//div[@class='message alert']"));
        assertEquals("Unexpected status text after adding end entity", "Request has been sent for approval.", messageInfo.getText());
    }

    @Test
    public void testC_findPending() {
        webDriverSuperAdmin.get(getRaWebUrl());
        // Page is refreshed, wait for it...
        webDriverSuperAdminWait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//a[@class='pure-menu-link requests-menu-link']")));
        webDriverSuperAdmin.findElement(By.xpath("//a[@class='pure-menu-link requests-menu-link']")).click();
        webDriverSuperAdmin.findElement(By.xpath("//a[@href='managerequests.xhtml?tab=pending']")).click();

        WebElement requestsTable = webDriverSuperAdmin.findElement(By.id("manageRequestsForm:manageRequestTable"));
        try {
            requestId = Integer.parseInt(requestsTable.findElement(By.xpath(".//tbody/tr/td/span")).getText());
            requestsTable.findElement(By.xpath(".//td[contains(text(),'ECAQA98TestCA')]"));
            requestsTable.findElement(By.xpath(".//td[contains(text(),'Add End Entity')]"));
            requestsTable.findElement(By.xpath(".//span[contains(text(), 'EcaQa98EE')]"));
            requestsTable.findElement(By.xpath(".//td[contains(text(),'Waiting for Approval')]"));
            requestsTable.findElement(By.id("manageRequestsForm:manageRequestTable:0:viewMoreButton"));
        } catch (NoSuchElementException e) {
            fail("Failed to locate correct approval request: " + e.getMessage());
        } catch (NumberFormatException e) {
            fail("Request Id was not found or not numeric");
        }
    }

    @Test
    public void testD_editRequest() {
        webDriverAdmin1.get(getRaWebUrl());
        // Page is refreshed, wait for it...
        webDriverAdmin1Wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//a[@class='pure-menu-link requests-menu-link']")));
        webDriverAdmin1.findElement(By.xpath("//a[@class='pure-menu-link requests-menu-link']")).click();

        try {
            //TODO Verify date and regex of Id
            webDriverAdmin1.findElement(By.xpath("//td[contains(text(),'ECAQA98TestCA')]"));
            webDriverAdmin1.findElement(By.xpath("//td[contains(text(),'Add End Entity')]"));
            webDriverAdmin1.findElement(By.xpath("//span[contains(text(), 'EcaQa98EE')]"));
            webDriverAdmin1.findElement(By.xpath("//td[contains(text(),'Waiting for Approval')]"));
        } catch (NoSuchElementException e) {
            fail("Failed to locate correct approval request: " + e.getMessage());
        }

        webDriverAdmin1.findElement(By.id("manageRequestsForm:manageRequestTable:0:viewMoreButton")).click();

        try {
            webDriverAdmin1.findElement(By.id("manageRequestForm:commandApprove"));
            webDriverAdmin1.findElement(By.id("manageRequestForm:commandReject"));
        } catch (NoSuchElementException e) {
            fail(getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMIN) + ": Approve and Reject button not found while reviewing request: " + e.getMessage());
        }

        webDriverAdmin1.findElement(By.id("manageRequestForm:commandEditData")).click();
        WebElement cnLabel = webDriverAdmin1.findElement(By.xpath("//label[contains(text(), 'CN, Common Name')]"));
        cnLabel.findElement(By.xpath("../span/input")).sendKeys("_Modified");
        webDriverAdmin1.findElement(By.id("manageRequestForm:commandSaveData")).click();

        try {
            webDriverAdmin1.findElement(By.xpath("//span[contains(text(), 'CN=" + eeName + "_Modified')]"));
        } catch (NoSuchElementException e) {
            fail("Unexpected CN after edit. Expected: CN=" + eeName + "_Modified");
        }
        WebElement approveMessage = webDriverAdmin1.findElement(By.id("manageRequestForm:requestApproveMessage"));
        assertEquals("Unexpected message after editing approval", "You have edited this request and cannot approve it", approveMessage.getText());
        try {
            webDriverAdmin1.findElement(By.id("manageRequestForm:commandApprove"));
            webDriverAdmin1.findElement(By.id("manageRequestForm:commandReject"));
            fail("Administrator was able to take action on request after editing it.");
        } catch (NoSuchElementException e) {} //Expected since buttons shouldn't be rendered after editing request
    }

    @Test
    public void testE_approvePostEdit() {
        webDriverAdmin2.get(getRaWebUrl());
        webDriverAdmin2Wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//a[@class='pure-menu-link requests-menu-link']")));
        webDriverAdmin2.findElement(By.xpath("//a[@class='pure-menu-link requests-menu-link']")).click();

        try {
            //TODO Verify date and regex of Id
            webDriverAdmin2.findElement(By.xpath("//td[contains(text(),'ECAQA98TestCA')]"));
            webDriverAdmin2.findElement(By.xpath("//td[contains(text(),'Add End Entity')]"));
            webDriverAdmin2.findElement(By.xpath("//span[contains(text(), 'EcaQa98EE')]"));
            webDriverAdmin2.findElement(By.xpath("//td[contains(text(),'Waiting for Approval')]"));
        } catch (NoSuchElementException e) {
            fail("Failed to locate correct approval request: " + e.getMessage());
        }

        webDriverAdmin2.findElement(By.id("manageRequestsForm:manageRequestTable:0:viewMoreButton")).click();

        try {
            webDriverAdmin2.findElement(By.id("manageRequestForm:commandApprove"));
            webDriverAdmin2.findElement(By.id("manageRequestForm:commandReject"));
        } catch (NoSuchElementException e) {
            fail(getProfileName(ConfigurationConstants.PROFILE_FIREFOX_RAADMINALT) + ": Approve and Reject button not found while reviewing request: " + e.getMessage());
        }

        webDriverAdmin2.findElement(By.id("manageRequestForm:commandApprove")).click();
        WebElement approvalMessage = webDriverAdmin2.findElement(By.id("manageRequestForm:requestApproveMessage"));
        assertEquals("Unexpected message after approving the edited request", "This request has been approved and executed already", approvalMessage.getText());
        try {
            webDriverAdmin2.findElement(By.xpath("//span[contains(text(), 'CN=" + eeName + "_Modified')]"));
        } catch (NoSuchElementException e) {
            fail("Unexpected CN after appoving edit. Expected: CN=" + eeName + "_Modified");
        }
    }
}