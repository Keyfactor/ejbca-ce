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

import static org.junit.Assert.*;

import java.util.List;

import org.ejbca.WebTestBase;
import org.ejbca.utils.ConfigurationConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * 
 * This test verifies the role template and access rules of Super Administrator template. In order to run the test, a Firefox profile
 * containing a superadmin certificate as first selection is required. The profile name can either be specified in /conf/profiles.properties
 * or a new Firefox profile can be created with the name 'superadmin'.
 * 
 * @version $Id: EcaQa78_SuperAdminAccess.java 28066 2018-01-22 16:30:07Z henriks $
 * 
 */
public class EcaQa78_SuperAdminAccess extends WebTestBase {
    
    private static WebDriver webDriver;
    
    @BeforeClass
    public static void init() {
        setUp(true, ConfigurationConstants.PROFILE_FIREFOX_SUPERADMIN);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() {
        webDriver.quit();
    }
    
    @Test
    public void verifyAccessRules() {
        webDriver.get(getAdminWebUrl());
        WebElement adminRolesLink = webDriver.findElement(By.xpath("//a[contains(@href,'ejbca/adminweb/administratorprivileges/roles.xhtml')]"));
        adminRolesLink.click();
        
        WebElement rolesListTable = webDriver.findElement(By.id("roles:list"));
        WebElement superAdminRow = rolesListTable.findElement(By.xpath(".//td[contains(text(), 'Super Administrator Role')]"));
        
        try {
            // role id 1 is expected to be superadmin
            superAdminRow.findElement(By.xpath("../td/a[@href='rolemembers.xhtml?roleId=1']"));
            superAdminRow.findElement(By.xpath("../td/a[@href='accessrules.xhtml?roleId=1']"));
            superAdminRow.findElement(By.xpath("../td/div/input[@value='Rename']"));
            superAdminRow.findElement(By.xpath("../td/div/input[@value='Delete']"));
            webDriver.findElement(By.xpath("//input[@value='Add']"));
        } catch (NoSuchElementException e) {
            fail("Failed to locate link or button in admin roles: " + e.getMessage());
        }
        
        superAdminRow.findElement(By.xpath("../td/a[@href='accessrules.xhtml?roleId=1']")).click();
        
        try {
            assertEquals("Unexpected header at 'Edit Access Rules' page","Administrator Role : Super Administrator Role", webDriver.findElement(By.xpath("//h2")).getText());
            assertEquals("Unexpected link text", "Back to Administrator Roles", webDriver.findElement(By.xpath("//a[@href='roles.xhtml']")).getText());
            assertEquals("Unexpected link text", "Members", webDriver.findElement(By.xpath("//a[@href='rolemembers.xhtml?roleId=1']")).getText());
            assertEquals("Unexpected link text", "Advanced Mode", webDriver.findElement(By.xpath("//a[@href='accessrules.xhtml?roleId=1&advanced=true']")).getText());
            webDriver.findElement(By.xpath("//input[@value='Save']"));
        } catch (NoSuchElementException e) {
            fail("Could not locate item on page 'Edit Access Rules': " + e.getMessage());
        }
        
        Select roleTemplate = new Select(webDriver.findElement(By.id("accessRulesForm:selectrole")));
        Select authCas = new Select(webDriver.findElement(By.id("accessRulesForm:selectcas")));
        Select eeRules = new Select(webDriver.findElement(By.id("accessRulesForm:selectendentityrules")));
        Select eeps = new Select(webDriver.findElement(By.id("accessRulesForm:selectendentityprofiles")));
        Select validators = new Select(webDriver.findElement(By.id("accessRulesForm:selectkeyvalidators")));
        Select intKeyBindings = new Select(webDriver.findElement(By.id("accessRulesForm:selectinternalkeybindingrules")));
        Select otherRules = new Select(webDriver.findElement(By.id("accessRulesForm:selectother")));
        
        assertEquals("Role template was not 'Super Administrators'", "Super Administrators", roleTemplate.getFirstSelectedOption().getText());
        assertEquals("All CAs was not authorized for Super Admin Template", "All", authCas.getFirstSelectedOption().getText());
        assertEquals("All End entity rules was not authorized for Super Admin Template", eeRules.getOptions().size(), eeRules.getAllSelectedOptions().size());
        assertEquals("All End entity profiles was not authorized for Super Admin Template", "All", eeps.getFirstSelectedOption().getText());
        assertEquals("All validators was not authorized for Super Admin Template", "All", validators.getFirstSelectedOption().getText());
        assertEquals("All Internal key bindings was not authorized for Super Admin Template", intKeyBindings.getOptions().size(), intKeyBindings.getAllSelectedOptions().size());
        assertEquals("All 'Other rules' was not authorized for Super Admin Template", otherRules.getOptions().size(), otherRules.getAllSelectedOptions().size());
        
        assertEquals("Authorized CAs was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectcas")).getAttribute("disabled"));
        assertEquals("End Entity Rules was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectendentityrules")).getAttribute("disabled"));
        assertEquals("End Entity Profiles was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectendentityprofiles")).getAttribute("disabled"));
        assertEquals("Validators was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectkeyvalidators")).getAttribute("disabled"));
        assertEquals("Internal Keybinding Rules was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectinternalkeybindingrules")).getAttribute("disabled"));
        assertEquals("Other Rules was not disabled", "true", webDriver.findElement(By.id("accessRulesForm:selectother")).getAttribute("disabled"));
        
        // Go to advanced mode
        webDriver.findElement(By.xpath("//a[@href='accessrules.xhtml?roleId=1&advanced=true']")).click();
        WebElement radioRoot = webDriver.findElement(By.xpath("//span[contains(text(),'/')]"));
        // Verify root ('/') is allowed
        radioRoot.findElement(By.xpath("../..//input[contains(@checked, 'checked') and contains(@value, 'ALLOW')]"));
        
        List<WebElement> allRules = webDriver.findElements(By.xpath("//table[@class='selectStateRadio']"));
        // Remove root (should always be first encountered element in DOM)
        allRules.remove(0);
        for (WebElement rule : allRules) {
            WebElement checkedRadio = rule.findElement(By.xpath(".//input[@checked='checked']"));
            assertEquals("UNDEFINED", checkedRadio.getAttribute("value"));
        }
    }
}