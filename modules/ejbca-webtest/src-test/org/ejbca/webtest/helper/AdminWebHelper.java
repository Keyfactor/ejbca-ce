package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * Admin Web helper class for EJBCA Web Tests.
 *
 * @version $Id:
 */
public class AdminWebHelper extends BaseHelper {
    /**
     * Public constructor.
     *
     * @param webDriver web driver.
     */
    public AdminWebHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Contains constants and references of the 'RA Web' page.
     */
    public static class Page {
        public static final String PAGE_URI = "/ejbca/adminweb/";
        public static final By HOME = By.id("home");
    }


    /**
     * Opens the 'Admin Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByUrlAndAssert(webUrl, Page.PAGE_URI);
    }
}
