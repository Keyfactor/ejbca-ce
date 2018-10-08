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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

// TODO JavaDoc
/**
 * RA Web helper class for EJBCA Web Tests.
 *
 * @version $Id: RaWebHelper.java 28908 2018-05-10 07:51:54Z andrey_s_helmes $
 */
public class RaWebHelper extends BaseHelper {

    public RaWebHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/ra/";
        //
        public static final By BUTTON_MAKE_NEW_REQUEST = By.id("makeRequestButton");
        public static final By SELECT_CERTIFICATE_TYPE = By.id("requestTemplateForm:selectEEPOneMenu");
        public static final By SELECT_CERTIFICATE_SUBTYPE = By.id("requestTemplateForm:selectCPOneMenu");
        public static final By SELECT_KEY_ALGORITHM = By.id("requestInfoForm:selectAlgorithmOneMenu");
        public static final By RADIO_BUTTON_KEY_PAIR_ON_SERVER = By.id("requestTemplateForm:selectKeyPairGeneration:0");
        public static final By RADIO_BUTTON_KEY_PAIR_PROVIDED = By.id("requestTemplateForm:selectKeyPairGeneration:1");
        public static final By LABELS_GROUP_PROVIDE_REQUEST_INFO = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        public static final By LABEL_COMMON_NAME = By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label");
        public static final By LABELS_GROUP_PROVIDE_USER_CREDENTIALS = By.xpath("//div[@id='requestInfoForm:userCredentialsOuterPanel']//label");
        public static final By BUTTON_SHOW_DETAILS = By.xpath("//div[@id='requestTemplateForm:selectRequestTemplateOuterPanel']//input[@value='Show details']");
        public static final By TEXTAREA_CERTIFICATE_REQUEST = By.id("keyPairForm:certificateRequest");
        public static final By BUTTON_UPLOAD_CSR = By.id("keyPairForm:uploadCsrButton");
        public static final By TEXT_ERROR_MESSAGE = By.xpath("//li[@class='errorMessage']");
    }

    /**
     * Opens the 'RA Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }

    public void makeNewCertificateRequest() {
        clickLink(Page.BUTTON_MAKE_NEW_REQUEST);
    }

    public void selectCertificateTypeByEndEntityName(final String endEntityProfileName) {
        selectOptionByName(Page.SELECT_CERTIFICATE_TYPE, endEntityProfileName);
    }

    public void selectKeyPairGenerationOnServer() {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_ON_SERVER);
    }

    public void selectKeyPairGenerationProvided() {
        clickLink(Page.RADIO_BUTTON_KEY_PAIR_PROVIDED);
    }

    public void assertCorrectProvideRequestInfoBlock() {
        final List<WebElement> provideRequestInfoWebElements = findElements(Page.LABELS_GROUP_PROVIDE_REQUEST_INFO);
        assertEquals("Unexpected number of fields under 'Provide request info'", 1, provideRequestInfoWebElements.size());
        final WebElement cnWebElement = findElement(Page.LABEL_COMMON_NAME);
        assertNotNull("Common Name label was not found.", cnWebElement);
        assertEquals(
                "Expected the label to have the value 'CN, Common Name *'",
                "CN, Common Name *",
                cnWebElement.getText()
        );
    }

    public void assertCorrectProvideUserCredentialsBlock() {
        final List<WebElement> provideUserCredentialsWebElements = findElements(Page.LABELS_GROUP_PROVIDE_USER_CREDENTIALS);
        assertEquals("Unexpected number of fields under 'Provide User Credentials'", 4, provideUserCredentialsWebElements.size());
        assertEquals("Expected the label to have the value 'Username'", "Username", provideUserCredentialsWebElements.get(0).getText());
        assertEquals("Expected the label to have the value 'Enrollment code'", "Enrollment code", provideUserCredentialsWebElements.get(1).getText());
        assertEquals("Expected the label to have the value 'Confirm enrollment code'", "Confirm enrollment code", provideUserCredentialsWebElements.get(2).getText());
        assertEquals("Expected the label to have the value 'Email'", "Email", provideUserCredentialsWebElements.get(3).getText());
    }

    public void clickShowDetailsButton() {
        clickLink(Page.BUTTON_SHOW_DETAILS);
    }

    public void assertCertificateProfileSelection(final String certificateProfileValue, final boolean isEnabled) {
        final WebElement certificateProfileSelectionWebElement = findElement(Page.SELECT_CERTIFICATE_SUBTYPE);
        assertNotNull("Certificate Profile selection was not found", certificateProfileSelectionWebElement);
        assertEquals("Certificate Profile selection is wrong", certificateProfileValue, certificateProfileSelectionWebElement.getText());
        assertEquals("Certificate Profile selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, certificateProfileSelectionWebElement.isEnabled());
    }

    public void assertKeyAlgorithmSelection(final String keyAlgorithmValue, final boolean isEnabled) {
        final WebElement keyAlgorithmSelectionWebElement = findElement(Page.SELECT_KEY_ALGORITHM);
        assertNotNull("Key Algorithm selection was not found.", keyAlgorithmSelectionWebElement);
        assertEquals("Key Algorithm selection is wrong", keyAlgorithmValue, keyAlgorithmSelectionWebElement.getText());
        assertEquals("Key Algorithm selection was not restricted (enabled = [" + isEnabled + "])", isEnabled, keyAlgorithmSelectionWebElement.isEnabled());
    }

    public void fillClearCsrText(final String csr) {
        fillTextarea(Page.TEXTAREA_CERTIFICATE_REQUEST, csr, true);
    }

    public void clickUploadCsrButton() {
        clickLink(Page.BUTTON_UPLOAD_CSR);
    }

    public void assertCsrUploadError() {
        final WebElement errorMessageWebElement = findElement(Page.TEXT_ERROR_MESSAGE);
        assertNotNull("No/wrong error message displayed when uploading forbidden CSR.", errorMessageWebElement);
        assertTrue("Error message does not match.", errorMessageWebElement.getText().contains("The key algorithm 'RSA_2048' is not available"));
    }

}
