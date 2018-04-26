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

package org.ejbca.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.ejbca.utils.WebTestUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

/**
 * 
 * Crypto Token helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenHelper {

    private CryptoTokenHelper() {}

    /**
     * Opens the 'Crypto Tokens' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href, 'cryptotokens.jsf')]")).click();
        assertEquals("Clicking 'Crypto Tokens' link did not redirect to expected page",
                WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/cryptotoken/cryptotokens.jsf");
    }

    /**
     * Checks that a given Crypto Token exists in the table.
     * 
     * @param webDriver the WebDriver to use
     * @param cryptoTokenName the name of the Crypto Token
     */
    public static void assertExists(WebDriver webDriver, String cryptoTokenName) {
        try {
            webDriver.findElement(By.xpath("//td/a/span[text()='" + cryptoTokenName + "']"));
        } catch (NoSuchElementException e) {
            fail(cryptoTokenName + " was not found in the Crypto Token table");
        }
    }
}
