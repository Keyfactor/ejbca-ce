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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

/**
 * 
 * Crypto Token helper class for EJBCA Web Tests.
 * 
 * @version $Id: CryptoTokenHelper.java 28852 2018-05-04 14:35:13Z oskareriksson $
 *
 */
public final class CryptoTokenHelper {

    private CryptoTokenHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

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
                WebTestUtil.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
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
