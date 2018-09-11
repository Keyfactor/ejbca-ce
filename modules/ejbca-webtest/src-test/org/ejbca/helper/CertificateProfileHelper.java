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

package org.ejbca.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.ejbca.utils.WebTestUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Certificate Profile helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 */
public final class CertificateProfileHelper {

    private static final String certificateProfileSaveMessage = "Certificate Profile saved.";

    private CertificateProfileHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /**
     * Opens the 'Manage Certificate Profiles' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href,'editcertificateprofiles.xhtml')]")).click();
        assertEquals("Clicking 'Certificate Profiles' link did not redirect to expected page",
                WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml");
    }

    /**
     * Adds a new Certificate Profile, and asserts that the add was successful.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     * @param assertSuccess true if an assertion should be made that the creation was successful
     */
    public static void add(WebDriver webDriver, String cpName, Boolean assertSuccess) {
        // Add Certificate Profile
        WebElement nameInput = webDriver.findElement(By.xpath("//input[contains(@name, 'editcertificateprofiles') and @type='text']"));
        nameInput.sendKeys(cpName);
        webDriver.findElement(By.xpath("//input[contains(@name, 'editcertificateprofiles') and @value='Add']")).click();
    
        if (assertSuccess) {
            // Assert add successful
            assertExists(webDriver, cpName);
        }
    }

    /**
     * Opens the edit page for a Certificate Profile, then asserts that the
     * correct Certificate Profile is being edited.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     */
    public static void edit(WebDriver webDriver, String cpName) {
        // Click edit button for Certificate Profile
        webDriver.findElement(By.xpath("//tr/td[text()='" + cpName + "']/following-sibling::td//input[@value='Edit']")).click();
    
        // Assert correct edit page
        WebElement editTitle = webDriver.findElement(By.xpath("//div/h3"));
        assertEquals("Unexpected title on Certificate Profile 'Edit' page",
                "Certificate Profile: " + cpName, editTitle.getText());
    }

    /**
     * Deletes a Certificate Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     * @param confirm true if the deletion should be confirmed, false if it should be cancelled
     */
    public static void delete(WebDriver webDriver, String cpName, boolean confirm) {
        // Click 'Delete' button
        webDriver.findElement(By.xpath("//tr/td[text()='" + cpName + "']/following-sibling::td//input[@value='Delete']")).click();

        // Assert that the correct Certificate Profile is being deleted
        WebElement toBeDeleted = webDriver.findElement(By.id("editcertificateprofiles:deleteProfileName"));
        assertEquals("The Certificate Profile being deleted is not correct", cpName, toBeDeleted.getText());

        if (confirm) {
            // Delete and assert deletion
            webDriver.findElement(By.xpath("//tr/td/input[@type='submit' and not(@value='Cancel')]")).click();
            assertTrue("Certificate Profile still exists, espected deletion",
                    webDriver.findElements(By.xpath("//tr/td[text()='" + cpName + "']")).isEmpty());
        } else {
            // Cancel deletion and assert Certificate Profile still exists
            webDriver.findElement(By.xpath("//tr/td/input[@type='submit' and @value='Cancel']")).click();
            assertExists(webDriver, cpName);
        }
    }

    /**
     * Renames a Certificate Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     * @param cpRename the new name
     */
    public static void rename(WebDriver webDriver, String cpName, String cpRename) {
        // Click 'Rename' button
        webDriver.findElement(By.xpath("//tr/td[text()='" + cpName + "']/following-sibling::td//input[@value='Rename']")).click();

        // Assert that the correct Certificate Profile is being renamed
        WebElement toBeRenamed = webDriver.findElement(By.id("editcertificateprofiles:renameProfileOld"));
        assertEquals("The Certificate Profile being renamed is not correct", cpName, toBeRenamed.getText());

        // Enter new name for Certificate Profile
        WebElement nameInput = webDriver.findElement(By.id("editcertificateprofiles:renameProfileNew"));
        nameInput.sendKeys(cpRename);
    
        // Rename Certificate Profile
        webDriver.findElement(By.xpath("//tr/td/input[@type='submit' and not(@value='Cancel')]")).click();
        assertExists(webDriver, cpRename);
    }

    /**
     * Clones a Certificate Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     * @param cpNameClone the name of the clone
     */
    public static void clone(WebDriver webDriver, String cpName, String cpNameClone) {
        // Click 'Clone' button
        webDriver.findElement(By.xpath("//tr/td[text()='" + cpName + "']/following-sibling::td//input[@value='Clone']")).click();

        // Assert that the correct Certificate Profile is being cloned
        WebElement toBeCloned = webDriver.findElement(By.id("editcertificateprofiles:addFromTemplateProfileOld"));
        assertEquals("The Certificate Profile being cloned is not correct", cpName, toBeCloned.getText());

        // Enter name for new Certificate Profile
        WebElement nameInput = webDriver.findElement(By.id("editcertificateprofiles:addFromTemplateProfileNew"));
        nameInput.sendKeys(cpNameClone);
    
        // Clone Certificate Profile
        webDriver.findElement(By.xpath("//tr/td/input[@type='submit' and not(@value='Cancel')]")).click();
        assertExists(webDriver, cpNameClone);
    }

    /**
     * Clicks the Save button when editing a Certificate Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param assertSuccess true if an assertion should be made that the "Certificate Profile Saved" message appeared.
     */
    public static void save(WebDriver webDriver, boolean assertSuccess) {
        webDriver.findElement(By.xpath("//input[@value='Save' and @type='submit']")).click();
        if (assertSuccess) {
            // Assert that the save was successful
            try {
                assertEquals("Expected profile save message was not displayed", certificateProfileSaveMessage, 
                        webDriver.findElement(By.xpath("//li[@class='infoMessage']")).getText());
            } catch (NoSuchElementException e) {
                fail("The Certificate Profile was not successfully saved");
            }
        }
    }

    /**
     * Checks that a given Certificate Profile exists in 'List of Certificate Profiles'.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     */
    public static void assertExists(WebDriver webDriver, String cpName) {
        try {
            webDriver.findElement(By.xpath("//tr/td[text()='" + cpName + "']"));
        } catch (NoSuchElementException e) {
            fail(cpName + " was not found in the List of Certificate Profiles");
        }
    }
}