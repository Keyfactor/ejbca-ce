package org.ejbca.webtest.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import java.util.List;
import java.util.Map;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Search End Entities helper class for EJBCA Web Tests.
 *
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
        static final By BUTTON_REVOKE_SELECTED = By.xpath("//input[@name='buttonrevokeusers']");
        static final By BUTTON_REACTIVE = By.xpath("//input[@value=\"Reactivate\"]");
        static final By BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED = By.id("viewModeSwitchBasicOrAdvanced");
        static final By BUTTON_SAVE_END_ENTITY = By.xpath("//input[@name='buttonedituser']");
        static final By BUTTON_RELOAD = By.xpath("//input[@name='buttonreload']");

        static final String TEXT_VIEW_MODE_SWITCH_BASIC = "Basic Mode";
        static final String TEXT_VIEW_MODE_SWITCH_ADVANCED = "Advanced Mode";
        // Select drop downs
        static final By SELECT_SEARCH_STATUS = By.xpath("//select[@name='selectliststatus']");
        static final By SELECT_REVOCATION_REASON = By.xpath("//select[@name=\"selectrevokereason\"]");
        // Other
        static final By ROWS_SEARCH_RESULTS = By.xpath("//table[@class='results']/tbody/tr");
        static final By TEXT_NO_RESULTS = By.xpath("//table[@class='results']/tbody//td[text()='No end entities found.']");

        static By getColumnContainingCommonName(final String cn) {
            return By.xpath("//table[@class='results']/tbody/tr/td[4][contains(text(),'" + cn + "')]");
        }
        static By getInputFieldLocatorByKey(final String key) {
            return By.xpath("//td[descendant-or-self::*[text()='" + key + "']]/following-sibling::td//input[not(@type='checkbox')]");
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
     * @param username            username.
     * @param certificateSn       certificate SN in hex.
     * @param endEntityStatusName name of the status to select.
     * @param expiringWithinDays  expiring value.
     */
    public void fillSearchCriteria(final String username, final String certificateSn, final String endEntityStatusName, final String expiringWithinDays) {
        if (username != null) {
            fillInput(Page.INPUT_SEARCH_USERNAME, username);
        }
        if (certificateSn != null) {
            fillInput(Page.INPUT_SEARCH_CERTIFICATE_SN, certificateSn);
        }
        if (endEntityStatusName != null) {
            selectOptionByName(Page.SELECT_SEARCH_STATUS, endEntityStatusName);
        }
        if (expiringWithinDays != null) {
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
        if (searchResultsWebElement == null) {
            fail("Cannot find search result rows.");
        }
        assertEquals("Unexpected number of End Entity results on search", numberOfResults, searchResultsWebElement.size());
        assertSearchResultIsNOTNoEntriesFound();
    }

    /**
     * Selects the checkbox of a first search resulting row.
     */
    public void triggerSearchResultFirstRowSelect() {
        clickLink(Page.INPUT_SEARCH_RESULT_FIRST_ROW_SELECT);
    }
    
    public void triggerSearchResultUsernameRowSelect(final String cn) {
        clickForRowEntry(cn, Page.INPUT_SEARCH_RESULT_FIRST_ROW_SELECT);
    }

    /**
     * Clicks the 'Delete Selected' button.
     */
    public void clickDeleteSelected() {
        clickLink(Page.BUTTON_DELETE_SELECTED);
    }

    /**
     * Clicks the specified element (button) for a row in search results.
     *
     * @param cn             Common Name of the row entry (used as row identifier)
     * @param elementToClick button to click
     */
    private void clickForRowEntry(final String cn, final By elementToClick) {
        final WebElement button = findElement(
                findElement(Page.getColumnContainingCommonName(cn)),
                elementToClick,
                true
        );
        if(button != null) {
            button.click();
        }
        else {
            fail("Cannot locate button in the row with CN=[" + cn + "]");
        }
    }

    /**
     * Clicks 'Edit' (End entity) for the row containing the specified CN.
     *
     * @param cn Common name of the row to use.
     */
    public void clickEditEndEntityForRow(final String cn) {
        clickForRowEntry(cn, Page.BUTTON_EDIT_END_ENTITY_FOR_ROW);
    }

    /**
     * Clicks 'View' (Certificate) for the row containing the specified CN.
     *
     * @param cn Common name of the row to use.
     */
    public void clickViewCertificateForRow(final String cn) {
        clickForRowEntry(cn, Page.BUTTON_VIEW_CERTIFICATE_FOR_ROW);
    }

    /**
     * Clicks 'View' (End entity) for the row containing the specified CN.
     *
     * @param cn Common name of the row to use.
     */
    public void clickViewEndEntityForRow(final String cn) {
        clickForRowEntry(cn, Page.BUTTON_VIEW_END_ENTITY_FOR_ROW);
    }

    /**
     * TODO Introduce common helper class for pop-up windows with more accurate, by field search.
     * <p>
     * Switches to first available pop-up window and asserts the given text exists.
     *
     * @param textToFind to assert existence of.
     */
    public void assertPopupContainsText(final String textToFind) {
        final String mainWindow = switchToNextWindow();
        assertElementExists(By.xpath("//*[text()[contains(.,'" + textToFind + "')]]"),
                "'" + textToFind + "' was not found in pop-up window.");
        switchToWindow(mainWindow);
    }

    /**
     * Asserts the search resulting table contains the row 'No end entities found.'.
     */
    public void assertNoSearchResults() {
        final WebElement noResultsWebElement = findElement(Page.TEXT_NO_RESULTS);
        if (noResultsWebElement == null) {
            fail("Cannot find no search result row.");
        }
        assertEquals(
                "Unexpected text in search table",
                "No end entities found.",
                noResultsWebElement.getText()
        );
    }
    
    /**
     * Asserts the search resulting table DOES NOT CONTAIN the 'No end entities found' row.
     */
    public void assertSearchResultIsNOTNoEntriesFound() {
        final WebElement noResultsWebElement = findElementWithoutWait(Page.TEXT_NO_RESULTS, false);
        assertNull("'No end entities found' message was found, but it must not be present.", noResultsWebElement);
    }

    /**
     * Switches the view to 'Basic Mode' if the link with proper text exists.
     */
    public void switchViewModeFromAdvancedToBasic() {
        if (Page.TEXT_VIEW_MODE_SWITCH_BASIC.equals(getElementText(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED))) {
            clickLink(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED);
        }
    }

    /**
     * Switches the view to 'Advanced Mode' if the link with proper text exists.
     */
    public void switchViewModeFromBasicToAdvanced() {
        if (Page.TEXT_VIEW_MODE_SWITCH_ADVANCED.equals(getElementText(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED))) {
            clickLink(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED);
        }
    }
    
    /**
     * Chooses a 'Revocation reason'.
     *
     * @param reason One of the options in the list.
     */
    public void chooseFromRevocationReason(final String reason) {
        selectOptionByName(Page.SELECT_REVOCATION_REASON, reason);
    }
    
    /**
     * Clicks the 'Revoke Selected' button.
     */
    public void clickRevokeSelected() {
        clickLink(Page.BUTTON_REVOKE_SELECTED);
    }
    
    /**
     * Clicks the 'Reactivate' button in certificate view.
     */
    public void clickReactive() {
        clickLink(Page.BUTTON_REACTIVE);
    }

    /**
     * Asserts the element 'Reactive' button is not shown on page.
     */
    public void assertReactiveButtonNotPresent() {
        assertNull(findElementWithoutWait(Page.BUTTON_REACTIVE, false));
    }

    public void acceptAlert() {
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
    }

    public void switchToPopup() {
        for (String windowHandle : webDriver.getWindowHandles()) {
            webDriver.switchTo().window(windowHandle);
        }
    }

    /**
     * Sets fields when editing an End Entity. in popup
     *
     * Can only be used to set fields which contain a single text field,
     * e.g. 'Username' and 'CN, Common name'.
     *
     * @param fieldMap a map with {Key->Value} entries on the form {'Username'->'User123', 'CN, Common name'->'John Doe'}
     */
    public void fillEndEntityEditFields(final Map<String, String> fieldMap) {
        for (final String key : fieldMap.keySet()) {
            fillInput(Page.getInputFieldLocatorByKey(key), fieldMap.get(key));
        }
    }

    /**
     * Clicks the 'Save' button in Edit End Entity popup
     */
    public void saveEndEntity() {
        clickLink(Page.BUTTON_SAVE_END_ENTITY);
    }

    /**
     * Clicks the 'Reload' button
     */
    public void reload() {
        clickLink(Page.BUTTON_RELOAD);
    }
}