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
        
        static String getCARowXPath(final String caName) {
            return "//td[1]/h3[contains(text(), '" + caName + "')]/ancestor::tr";
        }

        // Dynamic references
        static By getCARow (final String caName) {
            return By.xpath(getCARowXPath(caName));
        }
        
        static By getCrlUrl(final String caName, final int partitionNo) {
            int partitionRowNo = partitionNo + 1;
            return By.xpath(getCARowXPath(caName) + "/td[3]/table/tbody/tr[" + partitionRowNo + "]/td[5]/a");
        }
        
        /**
         * 
         * @param caName
         * @return the CRL URL or CRL URL for partition 0 in case of partitioned or MS-Compatible CA
         */
        static By getCrlUrl(final String caName) {
            return getCrlUrl(caName, 0);
        }

        static By getPreContainsCaName(final String caName) {
            return By.xpath("//pre[contains(text(), '" + caName + "')]");
        }
        
        static By getCrlCreateButonByCaName(final String caName) {
            return By.xpath(getCARowXPath(caName) + "/td[3]/form/input[2]");
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
    
    /**
     * Clicks the 'Get CRL' link with matching CA.
     * 
     * @param caName Name of CA. 
     */
    public void downloadCrl(final String caName) {
        clickLink(Page.getCrlUrl(caName));    
    }
    
    /**
     * Checks that 'Get CRL' number have been increased with matching CA.
     * 
     * @param caName Name of the CA. 
     */
    public void clickCrlLinkAndAssertNumberIncreased(final String caName){
        int crlNumber = getCrlNumber(caName);
        // Click 'Create CRL' button
        clickLink(Page.getCrlCreateButonByCaName(caName));
        // Make sure that the CRL number has been incremented
        assertEquals("The CRL number was not incremented.", crlNumber + 1, getCrlNumber(caName));
    }

    /**
     * Gets the number of 'Get CRL' with matching CA.
     * It will get partition 0 for partitioned or MS-compatible CAs.
     * 
     * @param caName Name of the CA.
     */
    public int getCrlNumber(String caName) {
        By elementCRLNumber = By.xpath(Page.getCARowXPath(caName) + "/td[3]/table/tbody/tr[1]/td[4]");
        String crlText = webDriver.findElement(elementCRLNumber).getText();
        return Integer.parseInt(crlText);
    }
}
