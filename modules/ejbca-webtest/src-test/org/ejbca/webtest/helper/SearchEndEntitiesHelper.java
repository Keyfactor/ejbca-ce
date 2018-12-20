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
 * @version $Id$
 */
public class SearchEndEntitiesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Search End Entities' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ra/listendentities.jsp";
        static final By PAGE_LINK = By.id("raListendentities");
        // Input fields
        static final By INPUT_SEARCH_USERNAME = By.xpath("//input[@name='textfieldusername']");
        static final By INPUT_SEARCH_CERTIFICATE_SN = By.xpath("//input[@name='textfieldserialnumber']");
        static final By INPUT_SEARCH_EXPIRING_WITHIN = By.xpath("//input[@name='textfielddays']");
        static final By INPUT_SEARCH_RESULT_FIRST_ROW_SELECT = By.xpath("//table[@class='results']/tbody/tr//input[@type='checkbox']");
        // Buttons
        static final By BUTTON_DELETE_SELECTED = By.xpath("//input[@name='buttondeleteusers']");
        static final By BUTTON_SEARCH_BY_USERNAME = By.xpath("//input[@name='buttonfind']");
        static final By BUTTON_SEARCH_BY_STATUS = By.xpath("//input[@name='buttonlist']");
        static final By BUTTON_VIEW_CERTIFICATE_FOR_ROW = By.xpath("./..//div[@class='button-group']/button[@title='View Certificates (popup window)']");
        static final By BUTTON_VIEW_END_ENTITY_FOR_ROW = By.xpath("./..//div[@class='button-group']/button[@title='View End Entity (popup window)']");
        static final By BUTTON_EDIT_END_ENTITY_FOR_ROW = By.xpath("./..//div[@class='button-group']/button[@title='Edit End Entity (popup window)']");
        static final By BUTTON_HARD_TOKEN_FOR_ROW = By.xpath("./..//div[@class='button-group']/button[@title='View Hard Tokens (popup window)']");
        // Select drop downs
        static final By SELECT_SEARCH_STATUS = By.xpath("//select[@name='selectliststatus']");
        // Other
        static final By ROWS_SEARCH_RESULTS = By.xpath("//table[@class='results']/tbody/tr");
        static final By TEXT_NO_RESULTS = By.xpath("//table[@class='results']/tbody//td[text()='No end entities found.']");
        
        static final By getColumnContainingCommonName(final String cn) {
            return By.xpath("//table[@class='results']/tbody/tr/td[4][contains(text(),'" + cn + "')]");
        }
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
     * Clicks the search by status button.
     */
    public void clickSearchByStatus() {
        clickLink(Page.BUTTON_SEARCH_BY_STATUS);
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
     * Clicks 'Edit' (End entity) for the row containing the specified CN.
     * @param cn Common name of the row to use.
     */
    public void clickEditEndEntityForRow(final String cn) {
        WebElement row = findElement(Page.getColumnContainingCommonName(cn));
        row.findElement(Page.BUTTON_EDIT_END_ENTITY_FOR_ROW).click();
    }
    
    /**
     * Clicks 'View' (Certificate) for the row containing the specified CN.
     * @param cn Common name of the row to use.
     */
    public void clickViewCertificateForRow(final String cn) {
        WebElement row = findElement(Page.getColumnContainingCommonName(cn));
        row.findElement(Page.BUTTON_VIEW_CERTIFICATE_FOR_ROW).click();
    }
    
    /**
     * Clicks 'View' (End entity) for the row containing the specified CN.
     * @param cn Common name of the row to use.
     */
    public void clickViewEndEntityForRow(final String cn) {
        WebElement row = findElement(Page.getColumnContainingCommonName(cn));
        row.findElement(Page.BUTTON_VIEW_END_ENTITY_FOR_ROW).click();
    }
    
    /**
     * Clicks 'Hard Tokens' for the row containing the specified CN.
     * @param cn Common name of the row to use.
     */
    public void clickHardTokensForRow(final String cn) {
        WebElement row = findElement(Page.getColumnContainingCommonName(cn));
        row.findElement(Page.BUTTON_HARD_TOKEN_FOR_ROW).click();
    }
    
    /**
     * TODO Introduce common helper class for pop-up windows with more accurate, by field search.
     * 
     * Switches to first available pop-up window and asserts the given text exists.
     * @param textToFind to assert existence of.
     */
    public void assertPopupContainsText(final String textToFind) {
        final String mainWindow = switchToNextWindow();
        assertElementExists(By.xpath("//*[text()[contains(.,'" + textToFind + "')]]"), 
                "'" + textToFind + "' was not found in pop-up window.");
        switchToWindow(mainWindow);
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
