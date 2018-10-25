package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

/**
 * Search End Entities helper class for EJBCA Web Tests.
 *
 * @version $Id: CertificateProfileHelper.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
public class SearchEndEntitiesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Search End Entities' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ra/listendentities.jsp";
        static final By PAGE_LINK = By.xpath("//li/a[contains(@href,'listendentities.jsp')]");
        //
        static final By INPUT_SEARCH_USERNAME = By.xpath("//input[@name='textfieldusername']");
        static final By BUTTON_SEARCH_BY_USERNAME = By.xpath("//input[@name='buttonfind']");
        static final By INPUT_SEARCH_CERTIFICATE_SN = By.xpath("//input[@name='textfieldserialnumber']");
        static final By SELECT_SEARCH_STATUS = By.xpath("//select[@name='selectliststatus']");
        static final By INPUT_SEARCH_EXPIRING_WITHIN = By.xpath("//input[@name='textfielddays']");
        static final By ROWS_SEARCH_RESULTS = By.xpath("//table[@class='results']/tbody/tr");
        static final By INPUT_SEARCH_RESULT_FIRST_ROW_SELECT = By.xpath("//table[@class='results']/tbody/tr//input[@type='checkbox']");
        static final By BUTTON_DELETE_SELECTED = By.xpath("//input[@name='buttondeleteusers']");
        static final By TEXT_NO_RESULTS = By.xpath("//table[@class='results']/tbody//td[text()='No end entities found.']");
    }

    public SearchEndEntitiesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'Search End Entities' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Fills search form if a search entry is not null.
     *
     * @param username username.
     * @param certificateSn certificate SN in hex.
     * @param endEntityStatusName name of the status to select.
     * @param expiringWithinDays expiring value.
     */
    public void fillSearchCriteria(final String username, final String certificateSn, final String endEntityStatusName, final String expiringWithinDays) {
        if(username != null) {
            fillInput(Page.INPUT_SEARCH_USERNAME, username);
        }
        if(certificateSn != null) {
            fillInput(Page.INPUT_SEARCH_CERTIFICATE_SN, certificateSn);
        }
        if(endEntityStatusName != null) {
            selectOptionByName(Page.SELECT_SEARCH_STATUS, endEntityStatusName);
        }
        if(expiringWithinDays != null) {
            fillInput(Page.INPUT_SEARCH_EXPIRING_WITHIN, expiringWithinDays);
        }
    }

    /**
     * Clicks the search by username button.
     */
    public void clickSearchByUsernameButton() {
        clickLink(Page.BUTTON_SEARCH_BY_USERNAME);
    }

    /**
     * Asserts the expected number of search results.
     *
     * @param numberOfResults number of results.
     */
    public void assertNumberOfSearchResults(final int numberOfResults) {
        final List<WebElement> searchResultsWebElement = findElements(Page.ROWS_SEARCH_RESULTS);
        if(searchResultsWebElement == null) {
            fail("Cannot find search result rows.");
        }
        assertEquals("Unexpected number of End Entity results on search", numberOfResults, searchResultsWebElement.size());
    }

    /**
     * Selects the checkbox of a first search resulting row.
     */
    public void triggerSearchResultFirstRowSelect() {
        clickLink(Page.INPUT_SEARCH_RESULT_FIRST_ROW_SELECT);
    }

    /**
     * Clicks the 'Delete Selected' button.
     */
    public void clickDeleteSelected() {
        clickLink(Page.BUTTON_DELETE_SELECTED);
    }

    /**
     * Operates with deletion confirmation alert dialog.
     *
     * @param expectedMessage expected message.
     * @param isConfirmed true to confirm, false otherwise.
     */
    public void confirmDeletionOfEndEntity(final String expectedMessage, final boolean isConfirmed) {
        assertAndConfirmAlertPopUp(expectedMessage, isConfirmed);
    }

    /**
     * Operates with revocation confirmation alert dialog.
     *
     * @param expectedMessage expected message.
     * @param isConfirmed true to confirm, false otherwise.
     */
    public void confirmRevocationOfEndEntity(final String expectedMessage, final boolean isConfirmed) {
        assertAndConfirmAlertPopUp(expectedMessage, isConfirmed);
    }

    /**
     * Asserts the search resulting table contains the row 'No end entities found.'.
     */
    public void assertNoSearchResults() {
        final WebElement noResultsWebElement = findElement(Page.TEXT_NO_RESULTS);
        if(noResultsWebElement == null) {
            fail("Cannot find no search result row.");
        }
        assertEquals(
                "Unexpected text in search table",
                "No end entities found.",
                noResultsWebElement.getText()
        );
    }
}
