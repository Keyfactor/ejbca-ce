package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Public Web helper class for EJBCA Web Tests.
 *
 * @version $Id:
 */
public class PublicWebHelper extends BaseHelper {
    /**
     * Public constructor.
     *
     * @param webDriver web driver.
     */
    public PublicWebHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/";

        public static final By ADMIN_WEB_LINK = By.xpath("//a[contains(@href,'/ejbca/adminweb/')]");
        public static final By MENU_HEADERS = By.xpath("//div[@class='menuheader']");
        public static final By MENU_ITEMS = By.xpath("//div[@class='menu']/ul/li/ul/li");
    }


    /**
     * Opens the 'Admin Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, PublicWebHelper.Page.PAGE_URI);
    }

    public void verifyAdminLinkText(final String expectedTitle, final String assertMessage){
        assertEquals(assertMessage, getElementText(Page.ADMIN_WEB_LINK), expectedTitle);
    }

    public void verifyAdminLinkUrl(final String expectedUri){
        clickLink(Page.ADMIN_WEB_LINK);
        //wait until page opens
        findElement(AdminWebHelper.Page.HOME);
        assertPageUri(expectedUri);
    }

    /**
     * Verify menu header's number and presence of elements
     * @param expectedHeadersNumber expected number of menu headers
     * @param expectedHeaders the list of headers ecpected to be present in menu
     */
    public void verifyMenuHeaders(final int expectedHeadersNumber, final List<String> expectedHeaders) {
        List<WebElement> menuHeaders = findElements(Page.MENU_HEADERS);
        assertEquals("Unexpected number of menu headers", expectedHeadersNumber, menuHeaders.size());
        List<String> foundMenuHeaders = new ArrayList<>();
        for (WebElement header : menuHeaders) {
            foundMenuHeaders.add(header.getText());
        }
        for (String expectedHeader : expectedHeaders) {
            assertTrue("Menu header missing from public web menu", foundMenuHeaders.contains(expectedHeader));
        }
    }

    /**
     * Verify number of menu items
     * @param expectedItemsNumber expected number of menu items without optional menu item
     * @param optionalMenuItems the headers of optional menu items.
     */
    public void verifyMenuItems(final int expectedItemsNumber, final String... optionalMenuItems) {
        List<WebElement> menuItems = findElements(Page.MENU_ITEMS);
        List<String> foundMenuItems = new ArrayList<>();
        List<String> optionalMenuItemList = Arrays.asList(optionalMenuItems);
        for (WebElement header : menuItems) {
            // We ignore the optional items when counting
            if (!optionalMenuItemList.contains(header.getText())) {
                foundMenuItems.add(header.getText());
            }
        }
        assertEquals("Unexpected number of menu items", expectedItemsNumber, foundMenuItems.size());
    }
}
