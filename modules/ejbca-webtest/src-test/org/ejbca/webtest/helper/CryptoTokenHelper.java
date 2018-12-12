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

/**
 * 
 * Crypto Token helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Crypto Tokens' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/cryptotoken/cryptotokens.xhtml";
        static final By PAGE_LINK = By.id("caCryptotokens");
        
        // Dynamic references
        static By getTokenOptionContainingText(final String text) {
            return By.xpath("//td/a/span[text()='" + text + "']");
        }
    }
    
    public CryptoTokenHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Crypto Tokens' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Checks that a given Crypto Token exists in the table of available tokens.
     * 
     * @param cryptoTokenName the name of the Crypto Token to check for.
     */
    public void assertTokenExists(String cryptoTokenName) {
        assertElementExists(
                Page.getTokenOptionContainingText(cryptoTokenName),
                cryptoTokenName + " was not found on 'Crypto Tokens' page."
        );
    }
}
