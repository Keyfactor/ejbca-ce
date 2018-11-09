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

import static org.junit.Assert.fail;

import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

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
        static final String PAGE_URI = "/ejbca/adminweb/ca/editcas/editcas.jsp";
        static final By PAGE_LINK = By.id("caEditcas");
        //
        static final By BUTTON_RENEW_CA = By.xpath("//input[@name='buttonrenewca']");
        static final By BUTTON_DELETE_CA = By.xpath("//input[@name='buttondeleteca']");
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
        WebElement nameInput = webDriver.findElement(By.xpath("//input[@name='textfieldcaname']"));
        nameInput.sendKeys(caName);
        webDriver.findElement(By.xpath("//input[@name='buttoncreateca']")).click();
    }
    
    /**
     * Selects CA from the list of CAs and clicks on 'Edit CA'
     * 
     * @param webDriver the WebDriver to use
     * @param caName the name of the CA to edit
     */
    public static void edit(WebDriver webDriver, String caName) {
        try {
            Select caList = new Select(webDriver.findElement(By.xpath("//select[@name='selectcas']")));
            caList.selectByVisibleText(caName + ", (Active)");
        } catch (NoSuchElementException e) {
            fail("Could not edit ca: " + caName + ". Was not found in list of CAs");
        }
        webDriver.findElement(By.xpath("//input[@name='buttoneditca']")).click();
    }
    
    /**
     * Saves & Creates the CA
     *
     */
    public void saveCa() {
        webDriver.findElement(By.xpath("//input[@name='buttoncreate' or @name='buttonsave']")).click();
    }

    /**
     * Sets the CA's Subject DN.
     * 
     * @param webDriver the WebDriver to use
     * @param subjectDn the Subject DN to set
     */
    public static void setSubjectDn(WebDriver webDriver, String subjectDn) {
        WebElement dnInput = webDriver.findElement(By.id("textfieldsubjectdn"));
        dnInput.clear();
        dnInput.sendKeys(subjectDn);
    }
    
    /**
     * Sets the CA's validity.
     *
     * @param validityString (*y *mo *d *h *m *s) or end date of the certificate. E.g. '1y'
     */
    public void setValidity(String validityString) {
        WebElement validityInput = webDriver.findElement(By.id("textfieldvalidity"));
        validityInput.sendKeys(validityString);
    }
    
    
    /**
     * Checks that a given CA exists in 'List of Certificate Authorities'.
     *
     * @param caName the name of the Certificate Profile
     */
    public void assertExists(String caName) {
        try {
            Select caList = new Select(webDriver.findElement(By.xpath("//select[@name='selectcas']")));
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
}
