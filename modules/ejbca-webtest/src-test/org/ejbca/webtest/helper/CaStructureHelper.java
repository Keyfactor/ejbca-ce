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

import org.apache.commons.lang.StringUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * @version $Id: CaStructureHelper.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
public class CaStructureHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'CA Structure & CRLs' page.
     */
    public static class Page {

        // General
        static final String CRL_PAGE_URI = "/ejbca/adminweb/ca/cafunctions.xhtml";
        static final By CRL_PAGE_LINK = By.id("caCafunctions");


        // Dynamic references
        static By getCrlUrl(final String caName) {
            return By.xpath("//a[text()='Get CRL' and contains(@href, '" + caName + "')]");
        }

        static By getPreContainsCaName(final String caName) {
            return By.xpath("//pre[contains(text(), '" + caName + "')]");
        }
    }

    public CaStructureHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'CA Structure & CRLs' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openCrlPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.CRL_PAGE_LINK, Page.CRL_PAGE_URI);
    }


    /**
     * Clicks to Crl url, opens Crl, checks opened crl contains CaName
     * @param caName
     */
    public void assertCrlLinkWorks(String caName ){
        String crlUrl = webDriver.findElement(Page.getCrlUrl(caName)).getAttribute("href");
        webDriver.get("view-source:" + crlUrl);
        try {
            webDriver.findElement(Page.getPreContainsCaName(caName));
        } catch (NoSuchElementException e) {
            fail("The CRL didn't contain the CA's name.");
        }
    }

    public void clickCrlLinkAndAssertNumberIncreased(String caName){
        String crlText = getCrlNumberAsString(caName);
        int crlNumber = Integer.parseInt(StringUtils.substringAfter(crlText, "number "));
        // Click 'Create CRL' button
        webDriver.findElement(CaHelper.Page.getCrlCreateButonByCaName(caName)).click();
        // Make sure that the CRL number has been incremented
        crlText = getCrlNumberAsString(caName);
        assertEquals("The CRL number was not incremented.", crlNumber + 1, Integer.parseInt(StringUtils.substringAfter(crlText, "number ")));
    }


    private String getCrlNumberAsString(String caName) {
        return StringUtils.substringBetween(webDriver.findElement(CaHelper.Page.CONTAINER).getText(), caName, " Get CRL");
    }
}
