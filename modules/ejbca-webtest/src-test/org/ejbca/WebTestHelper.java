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

package org.ejbca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.NoSuchElementException;

import org.ejbca.utils.WebTestUtils;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * Helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 */
public final class WebTestHelper {

    private static final String endEntityProfileSaveMessage = "End Entity Profile saved.";

    private WebTestHelper() {};

    /* --- Audit Log operations --- */
    /**
     * Opens the 'Audit Log' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goToAuditLog(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href,'audit/search.jsf')]")).click();
        assertEquals("Clicking 'View Log' link did not redirect to expected page",
                WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                        "/ejbca/adminweb/audit/search.jsf");
    }

    public static void assertAuditLogEvent(WebDriver webDriver, String event) {
        try {
            webDriver.findElement(By.xpath("//td[contains(text(), '" + event + "')]"));
        } catch (NoSuchElementException e) {
            fail("The event " + event + " was not found in the Audit Log");
        }
    }

    /**
     * Clicks the 'Reload' button on the 'Audit Log' page.
     * 
     * @param webDriver the WebDriver to use
     */
    public static void reloadAuditLog(WebDriver webDriver) {
        webDriver.findElement(By.xpath("//input[@class='commandLink reload']")).click();
    }

    /* --- End Entity Profile operations --- */
    /**
     * Opens the 'Manage End Entity Profiles' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goToEndEntityProfiles(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href,'editendentityprofiles.jsp')]")).click();
        assertEquals("Clicking 'End Entity Profiles' link did not redirect to expected page",
                WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                        "/ejbca/adminweb/ra/editendentityprofiles/editendentityprofiles.jsp");
    }

    /**
     * Adds a new End Entity Profile, and asserts that the add was successful.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     * @param assertSuccess true if an assertion should be made that the creation was successful
     */
    public static void addEndEntityProfile(WebDriver webDriver, String eepName, Boolean assertSuccess) {
        // Add End Entity Profile
        WebElement nameInput = webDriver.findElement(By.xpath("//input[@name='textfieldprofilename']"));
        nameInput.sendKeys(eepName);
        webDriver.findElement(By.xpath("//input[@name='buttonaddprofile']")).click();

        if (assertSuccess) {
            // Assert add successful
            assertEndEntityProfileExists(webDriver, eepName);
        }
    }

    /**
     * Selects an End Entity profile in 'List of End Entity Profiles'.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     */
    public static void selectEndEntityProfile(WebDriver webDriver, String eepName) {
        try {
            WebElement eepList = webDriver.findElement(By.xpath("//select[@name='selectprofile']"));
            WebElement eep = eepList.findElement(By.xpath("//option[@value='" + eepName + "']"));
            eep.click();
        } catch (NoSuchElementException e) {
            fail(eepName + " was not found in the List of End Entity Profiles");
        }
    }

    /**
     * Opens the edit page for an End Entity Profile, then asserts that the
     * correct End Entity Profile is being edited.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     */
    public static void editEndEntityProfile(WebDriver webDriver, String eepName) {
        // Select End Entity Profile in list
        selectEndEntityProfile(webDriver, eepName);

        // Click edit button
        webDriver.findElement(By.xpath("//input[@name='buttoneditprofile']")).click();

        // Assert correct edit page
        WebElement editTitle = webDriver.findElement(By.xpath("//div/h3"));
        assertEquals("Unexpected title in 'Edit End Entity Profile'",
                "End Entity Profile : " + eepName, editTitle.getText());
    }

    /**
     * Clones an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     * @param eepNameClone the name of the clone
     */
    public static void cloneEndEntityProfile(WebDriver webDriver, String eepName, String eepNameClone) {
        // Select End Entity Profile in list
        selectEndEntityProfile(webDriver, eepName);

        // Clone the End Entity Profile
        WebElement eepNameInput = webDriver.findElement(By.xpath("//input[@name='textfieldprofilename']"));
        eepNameInput.sendKeys(eepNameClone);
        webDriver.findElement(By.xpath("//input[@name='buttoncloneprofile']")).click();
    }

    /**
     * Renames an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     * @param eepRename the name of the clone
     */
    public static void renameEndEntityProfile(WebDriver webDriver, String eepName, String eepRename) {
        // Select End Entity Profile in list
        selectEndEntityProfile(webDriver, eepName);

        // Clone the End Entity Profile
        WebElement eepNameInput = webDriver.findElement(By.xpath("//input[@name='textfieldprofilename']"));
        eepNameInput.sendKeys(eepRename);
        webDriver.findElement(By.xpath("//input[@name='buttonrenameprofile']")).click();
    }

    /**
     * Deletes an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     */
    public static void deleteEndEntityProfile(WebDriver webDriver, String eepName) {
        // Select End Entity Profile in list
        selectEndEntityProfile(webDriver, eepName);

        // Click 'Delete End Entity Profile'
        webDriver.findElement(By.xpath("//input[@name='buttondeleteprofile']")).click();
    }

    /**
     * Clicks the Save button when editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param assertSuccess true if an assertion should be made that the save was successful
     */
    public static void saveEndEntityProfile(WebDriver webDriver, boolean assertSuccess) {
        webDriver.findElement(By.xpath("//input[@name='buttonsave']")).click();
        if (assertSuccess) {
            // Assert that the save was successful
            try {
                webDriver.findElement(By.xpath("//td[contains(text(), '" + endEntityProfileSaveMessage + "')]"));
            } catch (NoSuchElementException e) {
                fail("The End Entity Profile was not successfully saved");
            }
        }
    }

    /**
     * Checks that a given End Entity Profile exists in 'List of End Entity Profiles'.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     */
    public static void assertEndEntityProfileExists(WebDriver webDriver, String eepName) {
        try {
            WebElement eepList = webDriver.findElement(By.xpath("//select[@name='selectprofile']"));
            WebElement eep = eepList.findElement(By.xpath("//option[@value='" + eepName + "']"));
        } catch (NoSuchElementException e) {
            fail(eepName + " was not found in the List of End Entity Profiles");
        }
    }

    /**
     * Adds an attribute to 'Subject DN Attributes', 'Subject Alternative Name' or
     * 'Subject Directory Attributes' while editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param attributeType either 'subjectdn', 'subjectaltname' or 'subjectdirattr'
     * @param attributeName the displayed name of the attribute, e.g. 'O, Organization'
     */
    public static void addAttributeEndEntityProfile(WebDriver webDriver, String attributeType, String attributeName) {
        // Select attribute in list
        Select attributeSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectadd" + attributeType + "']")));
        attributeSelect.selectByVisibleText(attributeName);
        WebElement attributeItem = attributeSelect.getFirstSelectedOption();
        assertEquals("The attribute " + attributeName + " was not found", attributeName, attributeItem.getText());
        attributeItem.click();

        // Add attribute and assert that it was added
        webDriver.findElement(By.xpath("//input[@name='buttonadd" + attributeType + "']")).click();
        try {
            webDriver.findElement(By.xpath("//td[contains(text(), '" + attributeName + "')]"));
        } catch (NoSuchElementException e) {
            fail("The attribute " + attributeName + " was not added");
        }
    }

    /* --- Miscellaneous operations --- */
    /**
     * Used to assert that there was an alert, and optionally if there was a
     * specific alert message.
     * 
     * @param webDriver the WebDriver to use
     * @param expectedMessage the expected message from the alert (or null for no assertion)
     * @param accept true if the alert should be accepted, false if it should be dismissed
     */
    public static void assertAlert(WebDriver webDriver, String expectedMessage, boolean accept) {
        Boolean alertExists = true;
        try {
            Alert alert = webDriver.switchTo().alert();
            // Assert that the correct alert message is displayed (if not null)
            if (expectedMessage != null) {
                assertEquals("Unexpected alert message: " + alert.getText(), expectedMessage, alert.getText());
            }
            // Accept or dismiss the alert message
            if (accept) {
                alert.accept();
            } else {
                alert.dismiss();
            }
            webDriver.switchTo().defaultContent();
        } catch (NoAlertPresentException e) {
            // No alert found
            alertExists = false;
        }
        assertTrue("Expected an alert but there was none", alertExists);
    }
}
