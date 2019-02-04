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
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.PublicWebHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

import java.util.Arrays;

/**
 * 
 * @version $Id$
 *
 */
public class EcaQa64_PublicWebMenuItems extends WebTestBase {

    // Helpers
    private static PublicWebHelper publicWebHelper;

    // Test Data
    public static class TestData {
        final static int EXPECTED_NUMBER_OF_MENU_ITEMS = 13;
        final static int EXPECTED_NUMBER_OF_MENU_HEADERS = 5;
    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver  = getWebDriver();
        publicWebHelper = new PublicWebHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void testPublicWebMenuItems() {
        publicWebHelper.openPage(getPublicWebUrl());
        publicWebHelper.verifyMenuHeaders(TestData.EXPECTED_NUMBER_OF_MENU_HEADERS,
                Arrays.asList("Enroll", "Register", "Retrieve", "Inspect", "Miscellaneous"));
        publicWebHelper.verifyMenuItems(TestData.EXPECTED_NUMBER_OF_MENU_ITEMS, "Renew Browser Certificate");
    }

    // TODO ECA-7627 Documentation has to be built
    @Ignore
    @Test
    public void testDocumentationLink() {
//        webDriver.get(getPublicWebUrl()); // We are already here from previous test but try not to make test depend on each other
//        WebElement docsLink = webDriver.findElement(By.xpath("//a[@href='doc/index.html']"));
//        assertEquals("Unexpected name of documentation link", docsLink.getText(), "Documentation");
//        docsLink.click();
//        // Documentation link is opened in another tab
//        String currentTab = webDriver.getWindowHandle();
//        for (String tab: webDriver.getWindowHandles()) {
//            if (!tab.equals(currentTab)) {
//                webDriver.switchTo().window(tab);
//            }
//        }
//        assertEquals("Link didn't redirect to documentation page", "/ejbca/doc/concepts.html", WebTestUtil.getUrlIgnoreDomain(webDriver.getCurrentUrl()));
    }
    
    @Test
    public void testAdminWebLink() {
        publicWebHelper.openPage(getPublicWebUrl());
        publicWebHelper.verifyAdminLinkText("Administration", "Unexpected name of Admin web link");
        publicWebHelper.verifyAdminLinkUrl("/ejbca/adminweb/");
    }
}
