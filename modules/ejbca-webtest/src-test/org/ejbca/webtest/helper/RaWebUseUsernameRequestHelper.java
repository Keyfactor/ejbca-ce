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

import org.apache.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.interactions.Actions;

/**
 * RA Web helper class for EJBCA Web Tests.
 *
 */
public class RaWebUseUsernameRequestHelper extends BaseHelper {
    private static final Logger log = Logger.getLogger(RaWebUseUsernameRequestHelper.class);

    public RaWebUseUsernameRequestHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/ra/";
        static final By BUTTON_ENROLL = By.id("enrollment");
        static final By BUTTON_ENROLL_WITH_USERNAME = By.xpath("//a[@href='enrollwithusername.xhtml']");
        static final By INPUT_USERNAME = By.id("enrollWithUsernameForm:username");
        static final By INPUT_ENROLLMENTCODE = By.id("enrollWithUsernameForm:enrollmentCode");
        static final By BUTTON_CHECK = By.id("enrollWithUsernameForm:checkButton");
        static final By BUTTON_ENROLL_DOWNLOAD_PKCS12 = By.id("enrollWithUsernameForm:generatePkcs12");
        static final By BUTTON_ENROLL_DOWNLOAD_PEM = By.id("enrollWithUsernameForm:generatePem");
        static final By TEXTAREA_CERTIFICATE_REQUEST = By.id("enrollWithUsernameForm:certificateRequest");
        static final By BUTTON_UPLOAD_CSR = By.id("enrollWithUsernameForm:uploadCsrButton");
        static final By SELECT_KEY_ALGORITHM = By.id("enrollWithUsernameForm:selectAlgorithmOneMenu");
    }

    /**
     * Opens the 'RA Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }

    /**
     * Helps you hover over 'Enroll' and takes you to 'Use Username'.
     *
     */
    public void clickToEnrollUseUsername() {
        Actions action = new Actions(webDriver);
        action.moveToElement(webDriver.findElement(Page.BUTTON_ENROLL))
                .moveToElement(webDriver.findElement(Page.BUTTON_ENROLL_WITH_USERNAME))
                .click().build().perform();
    }

    /**
     * Fills the 'Username' and 'Enrollment code' textfields with text.
     *
     * @param username username
     * @param enrollmentCode enrollment code
     */
    public void fillEnrollUsernameAndCode(String username,String enrollmentCode) {
        fillInput(Page.INPUT_USERNAME, username );
        fillInput(Page.INPUT_ENROLLMENTCODE, enrollmentCode);
    }

    public void clickCheckButton() {
        clickLink(Page.BUTTON_CHECK);
    }
    
    /**
     * Paste CSR to textarea for upload
     * @param csr the request to be uploded
     */
    public void fillClearCsrText(final String csr) {
        fillTextarea(Page.TEXTAREA_CERTIFICATE_REQUEST, csr);
    }
    
    /**
     * Click to upload CSR
     */
    public void clickUploadCsrButton() {
        clickLink(Page.BUTTON_UPLOAD_CSR);
    }

    /**
     * Clicks the 'Download PKCS#12' button.
     * <p>
     * This method works in the 'Enroll - Use Username' workflow.
     * */
    public void clickEnrollDownloadPKCS12Button() {
        clickLink(Page.BUTTON_ENROLL_DOWNLOAD_PKCS12);
    }

    /**
     * Clicks the 'Download PEM' button.
     * <p>
     * This method works in the 'Enroll - Use Username' workflow.
     * */
    public void clickEnrollDownloadPemButton() {
        clickLink(Page.BUTTON_ENROLL_DOWNLOAD_PEM);
    }

    public void selectKeyAlgorithm(final String keyAlgorithm) {
        selectOptionByName(Page.SELECT_KEY_ALGORITHM, keyAlgorithm);
    }

}
