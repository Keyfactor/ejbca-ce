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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO JavaDoc
/**
 * Certificate Profile helper class for EJBCA Web Tests.
 *
 * @version $Id: CertificateProfileHelper.java 29858 2018-09-11 07:44:14Z andrey_s_helmes $
 */
public class CertificateProfileHelper extends BaseTestHelper {

    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        public static final String PAGE_URI = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        public static final By PAGE_LINK = By.id("caEditcertificateprofiles");
        // Certificate Profiles Form
        public static final By TEXT_MESSAGE = By.xpath("//*[@id='messages']//li[@class='infoMessage']");
        public static final By INPUT_NAME = By.id("editcertificateprofilesForm:editcertificateprofilesTable:profileNameInputField");
        public static final By BUTTON_ADD = By.id("editcertificateprofilesForm:editcertificateprofilesTable:addProfileButton");
        // Certificate Profile Form
        public static final By TEXT_TITLE_CERTIFICATE_PROFILE = By.id("titleCertificateProfile");
        public static final By SELECT_KEY_ALGORITHMS = By.id("cpf:selectavailablekeyalgorithms");
        public static final By SELECT_BIT_LENGTHS = By.id("cpf:selectavailablebitlengths");
        public static final By BUTTON_SAVE_PROFILE = By.id("cpf:saveProfileButton");
        // Dynamic references' parts
        public static final String TABLE_CERTIFICATE_PROFILES = "//*[@id='editcertificateprofilesForm:editcertificateprofilesTable']";

        // Dynamic references
        public static By getCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']");
        }

        public static By getEditButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Edit']");
        }

        public static By getDeleteButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Delete']");
        }

        public static By getRenameButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Rename']");
        }

        public static By getCloneButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Clone']");
        }
    }

    public CertificateProfileHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'Certificate Profiles' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a new Certificate Profile, and asserts that it appears in Certificate Profiles table.
     *
     * @param certificateProfileName a Certificate Profile name.
     */
    public void addCertificateProfile(final String certificateProfileName) {
        fillInput(Page.INPUT_NAME, certificateProfileName);
        clickLink(Page.BUTTON_ADD);
        assertCertificateProfileNameExists(certificateProfileName);
    }

    /**
     * Opens the edit page for a Certificate Profile, then asserts that the correct Certificate Profile is being edited.
     *
     * @param certificateProfileName a Certificate Profile name.
     */
    public void openEditCertificateProfilePage(final String certificateProfileName) {
        // Click edit button for Certificate Profile
        clickLink(Page.getEditButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert correct edit page
        assertCertificateProfileTitleExists(certificateProfileName);
    }

    public void editCertificateProfile(final List<String> selectedAlgorithms, final List<String> selectedBitLengths) {
        selectOptionsByName(Page.SELECT_KEY_ALGORITHMS, selectedAlgorithms);
        selectOptionsByName(Page.SELECT_BIT_LENGTHS, selectedBitLengths);
    }

    public void renameCertificateProfile(final String oldCertificateProfileName, final String newCertificateProfileName) {

    }

    public void deleteCertificateProfile(final String certificateProfileName) {

    }

    public void cloneCertificateProfile(final String certificateProfileName, final String newCertificateProfileName) {

    }

    public void saveCertificateProfile() {
        clickLink(Page.BUTTON_SAVE_PROFILE);
        assertCertificateProfileSaved();
    }

    private void assertCertificateProfileNameExists(final String certificateProfileName) {
        if(findElement(Page.getCPTableRowContainingText(certificateProfileName)) == null) {
            fail(certificateProfileName + " was not found on 'Certificate Profiles' page.");
        }
    }

    private void assertCertificateProfileTitleExists(final String certificateProfileName) {
        final WebElement certificateProfileTitle = findElement(Page.TEXT_TITLE_CERTIFICATE_PROFILE);
        if(certificateProfileName == null) {
            fail("Certificate Profile title was not found.");
        }
        assertEquals(
                "Unexpected title on Certificate Profile 'Edit' page",
                "Certificate Profile: " + certificateProfileName,
                certificateProfileTitle.getText()
        );
    }

    private void assertCertificateProfileSaved() {
        final WebElement certificateProfileSaveMessage = findElement(Page.TEXT_MESSAGE);
        if(certificateProfileSaveMessage == null) {
            fail("Certificate Profile save message was not found.");
        }
        assertEquals(
                "Expected profile save message was not displayed",
                "Certificate Profile saved.",
                certificateProfileSaveMessage.getText()
        );
    }

    //==================================================================================================================
    // TODO Refactor remaining
    //==================================================================================================================
    /**
     * Deletes a Certificate Profile.
     *
     * @param webDriver the WebDriver to use
     * @param cpName    the name of the Certificate Profile
     * @param confirm   true if the deletion should be confirmed, false if it should be cancelled
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
//            assertExists(cpName);
        }
    }

    /**
     * Renames a Certificate Profile.
     *
     * @param webDriver the WebDriver to use
     * @param cpName    the name of the Certificate Profile
     * @param cpRename  the new name
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
//        assertExists(cpRename);
    }

    /**
     * Clones a Certificate Profile.
     *
     * @param webDriver   the WebDriver to use
     * @param cpName      the name of the Certificate Profile
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
//        assertExists(webDriver, cpNameClone);
    }
}