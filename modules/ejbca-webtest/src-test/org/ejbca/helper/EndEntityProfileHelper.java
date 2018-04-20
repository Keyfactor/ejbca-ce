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

import java.util.List;

import org.ejbca.utils.WebTestUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * End Entity Profile helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 */
public final class EndEntityProfileHelper {

    private static final String endEntityProfileSaveMessage = "End Entity Profile saved.";

    private EndEntityProfileHelper() {}

    /**
     * Opens the 'Manage End Entity Profiles' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
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
    public static void add(WebDriver webDriver, String eepName, Boolean assertSuccess) {
        // Add End Entity Profile
        WebElement nameInput = webDriver.findElement(By.xpath("//input[@name='textfieldprofilename']"));
        nameInput.sendKeys(eepName);
        webDriver.findElement(By.xpath("//input[@name='buttonaddprofile']")).click();
    
        if (assertSuccess) {
            // Assert add successful
            EndEntityProfileHelper.assertExists(webDriver, eepName);
        }
    }

    /**
     * Selects an End Entity profile in 'List of End Entity Profiles'.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     */
    public static void select(WebDriver webDriver, String eepName) {
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
    public static void edit(WebDriver webDriver, String eepName) {
        // Select End Entity Profile in list
        select(webDriver, eepName);
    
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
    public static void clone(WebDriver webDriver, String eepName, String eepNameClone) {
        // Select End Entity Profile in list
        select(webDriver, eepName);
    
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
     * @param eepRename the new name
     */
    public static void rename(WebDriver webDriver, String eepName, String eepRename) {
        // Select End Entity Profile in list
        select(webDriver, eepName);
    
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
    public static void delete(WebDriver webDriver, String eepName) {
        // Select End Entity Profile in list
        select(webDriver, eepName);
    
        // Click 'Delete End Entity Profile'
        webDriver.findElement(By.xpath("//input[@name='buttondeleteprofile']")).click();
    }

    /**
     * Clicks the Save button when editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param assertSuccess true if an assertion should be made that the save was successful
     */
    public static void save(WebDriver webDriver, boolean assertSuccess) {
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
    public static void assertExists(WebDriver webDriver, String eepName) {
        try {
            WebElement eepList = webDriver.findElement(By.xpath("//select[@name='selectprofile']"));
            eepList.findElement(By.xpath("//option[@value='" + eepName + "']"));
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
    public static void addAttribute(WebDriver webDriver, String attributeType, String attributeName) {
        // Select attribute in list
        Select attributeSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectadd" + attributeType + "']")));
        attributeSelect.selectByVisibleText(attributeName);
        WebElement attributeItem = attributeSelect.getFirstSelectedOption();
        assertEquals("The attribute " + attributeName + " was not found", attributeName, attributeItem.getText());
    
        // Add attribute and assert that it was added
        webDriver.findElement(By.xpath("//input[@name='buttonadd" + attributeType + "']")).click();
        try {
            webDriver.findElement(By.xpath("//td[contains(text(), '" + attributeName + "')]"));
        } catch (NoSuchElementException e) {
            fail("The attribute " + attributeName + " was not added");
        }
    }

    /**
     * Sets the 'Default Certificate Profile' while editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the Certificate Profile
     */
    public static void setDefaultCertificateProfile(WebDriver webDriver, String cpName) {
        Select cpSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectdefaultcertprofile']")));
        cpSelect.selectByVisibleText(cpName);
        WebElement cpOption = cpSelect.getFirstSelectedOption();
        assertEquals("The Certificate Profile " + cpName + " was not found", cpName, cpOption.getText());
    }

    /**
     * Sets the 'Available Certificate Profiles' while editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpNames the names of the Certificate Profiles
     */
    public static void setAvailableCertificateProfile(WebDriver webDriver, List<String> cpNames) {
        Select cpSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectavailablecertprofiles']")));
        cpSelect.deselectAll();
        for (String cpName : cpNames) {
            cpSelect.selectByVisibleText(cpName);
            // Assert that there is a selected Certificate Profile with the name
            boolean selected = false;
            for (WebElement cpOption : cpSelect.getAllSelectedOptions()) {
                if (cpOption.getText().equals(cpName)) {
                    selected = true;
                }
            }
            assertTrue("The Certificate Profile " + cpName + " was not found", selected);
        }
    }

    /**
     * Sets the 'Default CA' while editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cpName the name of the CA
     */
    public static void setDefaultCA(WebDriver webDriver, String caName) {
        Select caSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectdefaultca']")));
        caSelect.selectByVisibleText(caName);
        WebElement caOption = caSelect.getFirstSelectedOption();
        assertEquals("The CA " + caName + " was not found", caName, caOption.getText());
    }

    /**
     * Sets the 'Available CAs' while editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param caNames the names of the CAs
     */
    public static void setAvailableCAs(WebDriver webDriver, List<String> caNames) {
        Select caSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectavailablecas']")));
        caSelect.deselectAll();
        for (String caName : caNames) {
            caSelect.selectByVisibleText(caName);
            // Assert that there is a selected CA with the name
            boolean selected = false;
            for (WebElement caOption : caSelect.getAllSelectedOptions()) {
                if (caOption.getText().equals(caName)) {
                    selected = true;
                }
            }
            assertTrue("The CA " + caName + " was not found", selected);
        }
    }
}