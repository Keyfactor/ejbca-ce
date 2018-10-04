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

package org.ejbca.webtest.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Helper class for handling 'Administrator Roles' page in automated web tests
 * @version $Id: AdminRolesHelper.java 29443 2018-07-03 12:46:36Z henriks $
 *
 */
public final class AdminRolesHelper {
    
    private AdminRolesHelper() {
        throw new AssertionError("Cannot instantiate class");
    }
    
    /**
     * Navigates to 'Administrator Roles' page and verifies outcome
     * @param webDriver the webDriver to use in navigation
     * @param adminWebUrl URL of EJBCA Admin Web
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href,'roles.xhtml')]")).click();
        assertEquals("Clicking 'Administrator Roles' link did not redirect to expected page",
                WebTestUtil.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/administratorprivileges/roles.xhtml");
    }
    
    /**
     * Adds a role
     * @param webDriver the webDriver to use in navigation
     * @param roleName to add
     * @param assertSuccess verify that the role was added to the list of administrator roles
     */
    public static void addRole(WebDriver webDriver, String roleName, boolean assertSuccess) {
        webDriver.findElement(By.xpath("//input[@value='Add' and @type='submit']")).click();
        webDriver.findElement(By.xpath("//input[@title='Mandatory role name']")).sendKeys(roleName);
        WebElement popupSpan = webDriver.findElement(By.id("modal:add"));
        popupSpan.findElement(By.xpath("..//input[@value='Add']")).click();
        
        if (assertSuccess) {
            assertExists(webDriver, roleName);
        }
    }
    
    /**
     * Edits access rules of the given role
     * @param webDriver the webDriver to use in navigation
     * @param roleName to edit
     */
    public static void editAccessRules(WebDriver webDriver, String roleName) {
        WebElement row = webDriver.findElement(By.xpath("//tr/td[text()='" + roleName + "']"));
        row.findElement(By.xpath("..//a[@title='Edit Access Rules']")).click();
    }
    
    /**
     * Checks that a given Administrator Role exists in list of Administrator Roles.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     */
    public static void assertExists(WebDriver webDriver, String roleName) {
        try {
            webDriver.findElement(By.xpath("//tr/td[text()='" + roleName + "']"));
        } catch (NoSuchElementException e) {
            fail(roleName + " was not found in the list of Administrator Roles");
        }
    }
}
