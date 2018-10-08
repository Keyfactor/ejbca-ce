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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

// TODO JavaDoc
/**
 * End Entity Profile helper class for EJBCA Web Tests.
 * 
 * @version $Id: EndEntityProfileHelper.java 28908 2018-05-10 07:51:54Z andrey_s_helmes $
 */
public class EndEntityProfileHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'End Entity Profiles' page.
     */
    public static class Page {
        // General
        public static final String PAGE_URI = "/ejbca/adminweb/ra/editendentityprofiles/editendentityprofiles.jsp";
        public static final By PAGE_LINK = By.id("raEditendentityprofiles");
        // End Entity Profiles Form
        public static final By TEXT_MESSAGE = By.xpath("//td[contains(text(), 'End Entity Profile saved.')]");
        public static final By INPUT_NAME = By.xpath("//input[@name='textfieldprofilename']");
        public static final By BUTTON_ADD = By.xpath("//input[@name='buttonaddprofile']");
        public static final By BUTTON_EDIT = By.xpath("//input[@name='buttoneditprofile']");
        public static final By SELECT_EE_PROFILES = By.xpath("//select[@name='selectprofile']");
        // End Entity Profile Form
        public static final By TEXT_TITLE_END_ENTITY_PROFILE = By.xpath("//div/h3");
        public static final By SELECT_DEFAULT_CERTIFICATE_PROFILE = By.xpath("//select[@name='selectdefaultcertprofile']");
        public static final By SELECT_AVAILABLE_CERTIFICATE_PROFILES = By.xpath("//select[@name='selectavailablecertprofiles']");
        public static final By SELECT_DEFAULT_CA = By.xpath("//select[@name='selectdefaultca']");
        public static final By SELECT_AVAILABLE_CAS = By.xpath("//select[@name='selectavailablecas']");
        public static final By BUTTON_SAVE_PROFILE = By.xpath("//input[@name='buttonsave']");
        // Dynamic references' parts

        // Dynamic references
        public static By getEEPOptionContainingText(final String text) {
            return By.xpath("//option[@value='" + text + "']");
        }
    }

    private static final String endEntityProfileSaveMessage = "";

    public EndEntityProfileHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'End Entity Profiles' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a new End Entity Profile, and asserts that it appears in End Entities Profiles table.
     *
     * @param endEntityProfileName an End Entity Profile name.
     */
    public void addEndEntityProfile(final String endEntityProfileName) {
        fillInput(Page.INPUT_NAME, endEntityProfileName);
        clickLink(Page.BUTTON_ADD);
        assertEndEntityProfileNameExists(endEntityProfileName);
    }

    /**
     * Opens the edit page for an End Entity Profile, then asserts that the correct End Entity Profile is being edited.
     *
     * @param endEntityProfileName an End Entity Profile name.
     */
    public void openEditEndEntityProfilePage(final String endEntityProfileName) {
        selectOptionByName(Page.SELECT_EE_PROFILES, endEntityProfileName);
        clickLink(Page.BUTTON_EDIT);
        assertEndEntityProfileTitleExists(endEntityProfileName);
    }

    public void editEndEntityProfile(final String defaultCertificateProfileName, final List<String> selectedCertificateProfiles, final String defaultCAName, final List<String> selectedCAs) {
        selectOptionByName(Page.SELECT_DEFAULT_CERTIFICATE_PROFILE, defaultCertificateProfileName);
        selectOptionsByName(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES, selectedCertificateProfiles);
        selectOptionByName(Page.SELECT_DEFAULT_CA, defaultCAName);
        selectOptionsByName(Page.SELECT_AVAILABLE_CAS, selectedCAs);
    }

    public void saveEndEntityProfile() {
        clickLink(Page.BUTTON_SAVE_PROFILE);
        assertEndEntityProfileSaved();
    }


    private void assertEndEntityProfileNameExists(final String endEntityProfileName) {
        final WebElement selectWebElement = findElement(Page.SELECT_EE_PROFILES);
        if(findElement(selectWebElement, Page.getEEPOptionContainingText(endEntityProfileName)) == null) {
            fail(endEntityProfileName + " was not found in the List of End Entity Profiles.");
        }
    }

    private void assertEndEntityProfileTitleExists(final String endEntityProfileName) {
        final WebElement endEntityProfileTitle = findElement(Page.TEXT_TITLE_END_ENTITY_PROFILE);
        if(endEntityProfileTitle == null) {
            fail("End Entity Profile title was not found.");
        }
        assertEquals(
                "Unexpected title on End Entity Profile 'Edit' page",
                "End Entity Profile : " + endEntityProfileName,
                endEntityProfileTitle.getText()
        );
    }

    private void assertEndEntityProfileSaved() {
        final WebElement endEntityProfileSaveMessage = findElement(Page.TEXT_MESSAGE);
        if(endEntityProfileSaveMessage == null) {
            fail("End Entity Profile save message was not found.");
        }
        assertEquals(
                "Expected profile save message was not displayed",
                "End Entity Profile saved.",
                endEntityProfileSaveMessage.getText()
        );
    }

    //==================================================================================================================
    // TODO Refactor remaining
    //==================================================================================================================

    /**
     * Clones an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param eepName the name of the End Entity Profile
     * @param eepNameClone the name of the clone
     */
    public static void clone(WebDriver webDriver, String eepName, String eepNameClone) {
        // Select End Entity Profile in list
//        select(webDriver, eepName);
    
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
//        select(webDriver, eepName);
    
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
//        select(webDriver, eepName);
    
        // Click 'Delete End Entity Profile'
        webDriver.findElement(By.xpath("//input[@name='buttondeleteprofile']")).click();
    }

    /**
     * Clicks the Cancel button when editing an End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     */
    public static void cancel(WebDriver webDriver) {
        webDriver.findElement(By.xpath("//input[@name='buttoncancel']")).click();
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

}