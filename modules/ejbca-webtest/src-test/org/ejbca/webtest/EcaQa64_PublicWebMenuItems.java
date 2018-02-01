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

package org.ejbca.webtest;

import org.ejbca.WebTestBase;
import org.ejbca.utils.WebTestUtils;
import org.junit.*;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.List;

/**
 * 
 * @version $Id$
 *
 */
public class EcaQa64_PublicWebMenuItems extends WebTestBase {

    private static WebDriver webDriver;
    
    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() {
        webDriver.quit();
    }

    @Test
    public void testPublicWebMenuItems() {
        int expectedNumberOfMenuItems = 13;
        int expectedNumberOfMenuHeaders = 5;
        HashMap<String, String> foundMenuHeaders = new HashMap<>();
        HashMap<String, String> foundMenuItems = new HashMap<>();

        webDriver.get(getPublicWebUrl());
        List<WebElement> menuHeaders = webDriver.findElements(By.xpath("//div[@class='menuheader']"));
        List<WebElement> allMenuItems = webDriver.findElements(By.xpath("//div[@class='menu']/ul/li/ul/li"));
        for (WebElement header : menuHeaders) {
            foundMenuHeaders.put(header.getText(), header.getText());
        }
        for (WebElement menuItem : allMenuItems) {
            foundMenuItems.put(menuItem.getText(), menuItem.getText());
        }
        // This is configurable for EJBCA (not available by default config)
        if (foundMenuItems.containsKey("Renew Browser Certificate")) {
            expectedNumberOfMenuItems++;
        }
        assertEquals("Unexpected number of menu items", expectedNumberOfMenuItems, foundMenuItems.size());
        assertEquals("Unexpected number of menu headers", expectedNumberOfMenuHeaders, foundMenuHeaders.size());
        assertTrue("Menu header missing from public web menu", foundMenuHeaders.containsKey("Enroll"));
        assertTrue("Menu header missing from public web menu", foundMenuHeaders.containsKey("Register"));
        assertTrue("Menu header missing from public web menu", foundMenuHeaders.containsKey("Retrieve"));
        assertTrue("Menu header missing from public web menu", foundMenuHeaders.containsKey("Inspect"));
        assertTrue("Menu header missing from public web menu", foundMenuHeaders.containsKey("Miscellaneous"));

    }

    @Test
    public void testDocumentationLink() {
        webDriver.get(getPublicWebUrl()); // We are already here from previous test but try not to make test depend on each other
        WebElement docsLink = webDriver.findElement(By.xpath("//a[@href='doc/concepts.html']"));
        assertEquals("Unexpected name of documentation link", docsLink.getText(), "Documentation");
        docsLink.click();
        // Documentation link is opened in another tab
        String currentTab = webDriver.getWindowHandle();
        for (String tab: webDriver.getWindowHandles()) {
            if (!tab.equals(currentTab)) {
                webDriver.switchTo().window(tab);
            }
        }
        assertEquals("Link didn't redirect to documentation page", "/ejbca/doc/concepts.html", WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()));


    }
    
    @Test
    public void testAdminWebLink() {
        webDriver.get(getPublicWebUrl());
        WebElement adminLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/')]"));
        assertEquals("Unexpected name of Admin web link", adminLink.getText(), "Administration");
        adminLink.click();
        assertEquals("Link didn't redirect to administration page", "/ejbca/adminweb/", WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()));
    }
}
