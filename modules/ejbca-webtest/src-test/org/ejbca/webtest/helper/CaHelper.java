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

import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import static org.junit.Assert.fail;

/**
 * 'Certificate Authorities' helper class for EJBCA Web Tests.
 * 
 * @version $Id: CaHelper.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
public class CaHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'CA' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editcas/managecas.xhtml";
        static final By PAGE_LINK = By.id("caEditcas");

        //
        static final By BUTTON_CREATE_CA = By.id("managecas:buttoncreateca");
        static final By BUTTON_SAVE = By.id("editcapage:buttoncreate");
        static final By BUTTON_EDIT = By.xpath("//input[@name='buttoneditca']");
        static final By BUTTON_RENEW_CA = By.xpath("//input[@name='buttonrenewca']");
        static final By BUTTON_DELETE_CA = By.xpath("//input[@name='buttondeleteca']");

        static final By SELECT_CA = By.id("managecas:selectcas");

        static final By INPUT_CANAME = By.id("managecas:textfieldcaname");
        static final By INPUT_VALIDITY = By.id("editcapage:textfieldvalidity");
        static final By INPUT_SUBJECT_DN = By.id("textfieldsubjectdn");

        // Dynamic references
        static By getCaTableRowContainingText(final String text) {
            return By.xpath("//td[text()='" + text + "']");
        }
    }

    public CaHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Certificate Authorities' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a new CA. Browser will end up in the edit page for this CA once method is done.
     *
     * @param caName the name of the CA
     */
    public void addCa(String caName) {
        fillInput(Page.INPUT_CANAME, caName);
        clickLink(Page.BUTTON_CREATE_CA);
    }
    
    /**
     * Selects CA from the list of CAs and clicks on 'Edit CA'
     *
     * @param caName the name of the CA to edit
     */
    public void edit(String caName) {
        try {
            Select caList = new Select(findElement(Page.SELECT_CA));
            caList.selectByVisibleText(caName + ", (Active)");
        } catch (NoSuchElementException e) {
            fail("Could not edit ca: " + caName + ". Was not found in list of CAs");
        }
        clickLink(Page.BUTTON_EDIT);
    }
    
    /**
     * Saves & Creates the CA
     *
     */
    public void saveCa() {
        clickLink(Page.BUTTON_SAVE);
    }

    /**
     * Sets the CA's Subject DN.
     *
     * @param subjectDn the Subject DN to set
     */
    public void setSubjectDn(String subjectDn) {
        WebElement dnInput = webDriver.findElement(Page.INPUT_SUBJECT_DN);
        dnInput.clear();
        dnInput.sendKeys(subjectDn);
        fillInput(Page.INPUT_SUBJECT_DN, subjectDn);
    }
    
    /**
     * Sets the CA's validity.
     *
     * @param validityString (*y *mo *d *h *m *s) or end date of the certificate. E.g. '1y'
     */
    public void setValidity(String validityString) {
        fillInput(Page.INPUT_VALIDITY, validityString);
    }
    
    
    /**
     * Checks that a given CA exists in 'List of Certificate Authorities'.
     *
     * @param caName the name of the Certificate Profile
     */
    public void assertExists(String caName) {
        try {
            Select caList = new Select(findElement(Page.SELECT_CA));
            caList.selectByVisibleText(caName + ", (Active)");
        } catch (NoSuchElementException e) {
            fail(caName + " was not found in the List of Certificate Authorities");
        }
    }

    /**
     * Calls the CA renew dialog
     *
     * @param expectedAlertMessage expected alert message.
     * @param isConfirmed true to confirm, false otherwise.
     * @param expectedTitle expected title message in of confirmed.
     * @param caName CA name.
     */
    public void renewCaAndAssert(final String expectedAlertMessage, final boolean isConfirmed, final String expectedTitle, final String caName) {
        clickLink(Page.BUTTON_RENEW_CA);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
        if(isConfirmed) {
            assertTitleExists(expectedTitle);
        }
        assertExists(caName);
    }

    /**
     * Calls the CA delete dialog.
     *
     * @param expectedAlertMessage expected alert message.
     * @param isConfirmed true to confirm, false otherwise.
     * @param expectedTitle expected title message in of confirmed.
     * @param caName CA name.
     */
    public void deleteCaAndAssert(final String expectedAlertMessage, final boolean isConfirmed, final String expectedTitle, final String caName) {
        clickLink(Page.BUTTON_DELETE_CA);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
        if(isConfirmed) {
            assertTitleExists(expectedTitle);
        }
        assertExists(caName);
    }

    private void assertTitleExists(final String titleText) {
        final WebElement titleWebElement = findElement(Page.getCaTableRowContainingText(titleText));
        if(titleWebElement == null) {
            fail("Title was not found [" + titleText + "].");
        }
    }

    // TODO Refactor ECA-7343
    public void selectApprovalProfileName(final String approvalProfileName) {
        List<WebElement> approvalDropDowns = webDriver.findElements(By.xpath("//select[contains(@name, ':approvalprofile')]"));
        for (WebElement approvalDropDown : approvalDropDowns) {
            new Select(approvalDropDown).selectByVisibleText(approvalProfileName);
        }
    }

}
