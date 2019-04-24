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
import org.openqa.selenium.WebDriver;

import static org.junit.Assert.assertEquals;

/**
 * 'CA Structure & CRLs' helper class for EJBCA Web Tests.
 * @version $Id$
 */
public class CaStructureHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'CA Structure & CRLs' page.
     */
    public static class Page {

        // General
        static final String CRL_PAGE_URI = "/ejbca/adminweb/ca/cafunctions.xhtml";
        static final By CRL_PAGE_LINK = By.id("caCafunctions");

        static final By CONTAINER = By.xpath("//div[@class='container']");

        // Dynamic references
        static By getCrlUrl(final String caName) {
            return By.xpath("//a[text()='Get CRL' and contains(@href, '" + caName + "')]");
        }

        static By getPreContainsCaName(final String caName) {
            return By.xpath("//pre[contains(text(), '" + caName + "')]");
        }
        static By getCrlCreateButonByCaName(final String caName) {
            return By.xpath("//a[text() = 'Get CRL' and contains(@href, 'CN=" + caName + "')]/following-sibling::form/input[contains(@value, 'Create CRL')]");
        }
    }

    public CaStructureHelper(final WebDriver webDriver) {
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
    public void assertCrlLinkWorks(final String caName ){
        String crlUrl = getElementHref(Page.getCrlUrl(caName));
        webDriver.get("view-source:" + crlUrl);
        assertElementExists(Page.getPreContainsCaName(caName), "The CRL didn't contain the CA's name.");
    }

    public void clickCrlLinkAndAssertNumberIncreased(final String caName){
        int crlNumber = getCrlNumber(caName);
        // Click 'Create CRL' button
        clickLink(Page.getCrlCreateButonByCaName(caName));
        // Make sure that the CRL number has been incremented
        assertEquals("The CRL number was not incremented.", crlNumber + 1, getCrlNumber(caName));
    }


    public int getCrlNumber(String caName) {
        String crlText = StringUtils.substringBetween(webDriver.findElement(Page.CONTAINER).getText(), caName, " Get CRL");
        return Integer.parseInt(StringUtils.substringAfter(crlText, "number "));
    }
}
