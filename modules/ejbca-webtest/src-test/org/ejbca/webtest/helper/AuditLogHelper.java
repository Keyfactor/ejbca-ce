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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.cesecore.util.ValidityDate;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

// TODO JavaDoc
/**
 * Audit Log helper class for EJBCA Web Tests.
 * 
 * Always reset filterTime before using the methods in this class, which makes sure
 * there only exists entries in the Audit Log for the test step currently executing.
 * 
 * @version $Id$
 */
public class AuditLogHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/audit/search.xhtml";
        static final By PAGE_LINK = By.id("supervisionAuditsearch");
        // Audit Log View
        static final By BUTTON_CLEAR_ALL_CONDITIONS = By.id("search:clearConditionsButton");
        static final By BUTTON_ADD_COLUMN = By.xpath("//input[contains(@value, 'Add...') and @type='submit']");
        static final By SELECT_FILTER_COLUMN = By.xpath("//select[contains(@id, 'conditionColumn')]");
        static final By BUTTON_APPLY_FILTERING_CONDITION = By.xpath("//input[contains(@src, 'success') and @type='image']");
        static final By INPUT_DISPLAY_START_POSITION = By.id("search2:startIndex2");
        static final By INPUT_NR_OF_RESULTS_PER_PAGE = By.id("search2:maxResults");
        static final By BUTTON_RELOAD_VIEW = By.xpath("//input[@class='commandLinkAudit reload']");
        static final By RESULT_ROWS = By.xpath("//table[caption[text()='Search results']]/tbody/tr");
        static final By RESULT_EVENT_COLUMN_CELLS = By.xpath("//table[caption[text()='Search results']]/tbody/tr/td[2]");

        /**
         * Child elements for Event Log Row.
         */
        public static class EVENT_LOG_ROW {
            static final By TEXT_OUTCOME = By.xpath("td[3]");
            static final By TEXT_CA = By.xpath("td[6]");
            static final By CONTAINER_DETAILS = By.xpath("(td[10]|td[10]/a/span)");
        }

        // Dynamic references
        static By getSelectFilterConditionByColumnName(final String columnName) {
            return By.xpath("//td[text()='" + columnName + "']/following-sibling::td[1]/select");
        }

        static By getFilterValueElementByColumnName(final String columnName) {
            return By.xpath("//td[text()='" + columnName + "']/following-sibling::td[2]/*");
        }

        static By getEventLogRowByEventText(final String eventText) {
            return By.xpath("//tr[td[2]/text()='" + eventText + "']");
        }

        static By getProtocolEnabled(final String protocol) {
            return By.xpath("//span[contains(text(),'msg=Saved global configuration with id AVAILABLE_PROTOCOLS.; changed:" + protocol + "=true')]");
        }
    }

    // Used to filter the Audit Log, only Audit Log entries after this time will be displayed
    private String defaultTimestampForFiltering;

    public AuditLogHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Resets the time to filter the Audit Log with. Only entries after the
     * last call of this method will be displayed in the Audit Log.
     */
    public void initFilterTime() {
        defaultTimestampForFiltering = ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_SERVER);
    }

    /**
     * Opens the 'Certificate Profiles' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
        configureFilteredView();
    }

    /**
     * Sets the "base" filtering for tests. Log entries from before the test are hidden, and the filtering and
     * pagination is otherwise set to the default (hiding Access Control events, and showing the first 40 results)
     */
    public void configureFilteredView() {
        // Set conditions
        clearConditions();
        setViewFilteringCondition("Event", "Not equals", "Access Control");
        setViewFilteringCondition("Time", "Greater than", defaultTimestampForFiltering);
        // Set 'Displaying results' and 'Entries per page' to standard values
        setViewPaginationProperties(1, 40);
        // Apply filters and pagination
        reloadView();
    }

    /**
     * Clears all filtering condition.
     */
    public void clearConditions() {
        clickLinkIfExists(Page.BUTTON_CLEAR_ALL_CONDITIONS);
    }

    /**
     * Adds a condition for filtering the Audit Log.
     *
     * Different values for 'Column' either results in a drop-down or a
     * text field for 'Value', which the method handles automatically.
     *
     * @param columnName
     * @param columnCondition
     * @param columnValue
     */
    public void setViewFilteringCondition(final String columnName, final String columnCondition, final String columnValue) {
        // Set 'Column'
        selectOptionByName(Page.SELECT_FILTER_COLUMN, columnName);
        clickLink(Page.BUTTON_ADD_COLUMN);
        // Set 'Condition'
        selectOptionByName(Page.getSelectFilterConditionByColumnName(columnName), columnCondition);
        // Set 'Value'
        final By valueElementReference = Page.getFilterValueElementByColumnName(columnName);
        // If text field, input the correct value
        if (isInputElement(valueElementReference)) {
            fillInput(valueElementReference, columnValue);
        }
        // If drop-down, select the correct value
        if (isSelectElement(valueElementReference)) {
            selectOptionByName(valueElementReference, columnValue);
        }
        // Apply the condition
        clickLink(Page.BUTTON_APPLY_FILTERING_CONDITION);
    }

    /**
     * Sets the pagination fields.
     * @param displayStartPositionNr The 'Displaying results' field, i.e. the index of the first result to show.
     * @param nrOfResultsPerPage The 'Entries per page' field, i.e. total number of results to show at most.
     */
    public void setViewPaginationProperties(final int displayStartPositionNr, final int nrOfResultsPerPage) {
        fillInput(Page.INPUT_DISPLAY_START_POSITION, "" + displayStartPositionNr);
        fillInput(Page.INPUT_NR_OF_RESULTS_PER_PAGE, "" + nrOfResultsPerPage);
    }

    /** Reloads the results. This will apply any changed filtering conditions. */
    public void reloadView() {
        clickLink(Page.BUTTON_RELOAD_VIEW);
    }

    /**
     * Asserts that a specific row is present in the results table. The row is searched for by the 'Event' column.
     *
     * @param eventText Event text to search for.
     * @param outcomeText If not null, this is the expected outcome ("Success" or "Failure").
     * @param certificateAuthorityText If not null, this is the expected name of Certification Authority.
     * @param detailsList If not null or empty, these strings are expected to appear in the 'Details' column of the row.
     */
    public void assertLogEntryByEventText(
            final String eventText,
            final String outcomeText,
            final String certificateAuthorityText,
            final List<String> detailsList) {

        // Find the row which has the event parameter as its 'Event' value
        final WebElement eventRowWebElement = findElement(Page.getEventLogRowByEventText(eventText));
        assertNotNull("The event [" + eventText + "] was not found in the Audit Log", eventRowWebElement);
        // Assert expected value of 'Outcome' field
        if (outcomeText != null) {
            final WebElement outcomeWebElement = findElement(eventRowWebElement, Page.EVENT_LOG_ROW.TEXT_OUTCOME);
            assertNotNull("Outcome field was not found.", outcomeWebElement);
            assertEquals("Unexpected outcome for event [" + eventText + "]", outcomeText, outcomeWebElement.getText());
        }
        // Assert expected value of 'Certificate Authority' field
        if (certificateAuthorityText != null) {
            final WebElement caWebElement = findElement(eventRowWebElement, Page.EVENT_LOG_ROW.TEXT_CA);
            assertNotNull("CA field was not found.", caWebElement);
            assertEquals("Unexpected CA for event [" + eventText + "]", certificateAuthorityText, caWebElement.getText());
        }
        // Extract value of 'Details' field, it is either a td element with text as its value
        // or a nested span element with text as its 'title' attribute
        if (detailsList != null && !detailsList.isEmpty()) {
            final WebElement detailsContainerWebElement = findElement(eventRowWebElement, Page.EVENT_LOG_ROW.CONTAINER_DETAILS);
            assertNotNull("Details field was not found.", detailsContainerWebElement);
            String detailsValue = "";
            if (isTdElement(detailsContainerWebElement)) {
                // Get value if it's a td element
                detailsValue = detailsContainerWebElement.getText();
            } else {
                // Get attribute 'title' if it's a span element
                detailsValue = detailsContainerWebElement.getAttribute("title");
            }
            // Assert that all detail substrings exists in 'Details' field
            for (final String detailText : detailsList) {
                assertTrue("The expected detail [" + detailText + "] for event [" + eventText + "] doesn't exist.", detailsValue.contains(detailText));
            }
        }
    }

    public void assertProtocolEnabledLogExists(final String protocol) {
        final WebElement addedElement = webDriver.findElement(Page.getProtocolEnabled(protocol));
        assertLogEntryByEventText("System Configuration Edit", "Success", null, Collections.singletonList(addedElement.getText()));
    }

    //==================================================================================================================
    // TODO Refactor remaining
    //==================================================================================================================

    /**
     * Returns the number of entries currently displayed in the Audit Log.
     * 
     * @param webDriver the WebDriver to use
     */
    public static int entryCount(WebDriver webDriver) {
        return webDriver.findElements(Page.RESULT_ROWS).size();
    }
    
    /**
     * Returns the "Event" column for all displayed audit log entries in the table, in the same order as in the table.
     * @param webDriver the WebDriver to use
     * @return List of text from the table cells in the "Event" column.
     */
    public static List<String> getEntries(final WebDriver webDriver) {
        final List<String> ret = new ArrayList<>();
        final List<WebElement> elements = webDriver.findElements(Page.RESULT_EVENT_COLUMN_CELLS);
        for (final WebElement element : elements) {
            ret.add(element.getText());
        }
        return ret;
    }
    
    /**
     * Checks that the expected events appear in the "Event" column in the audit log table.
     * The table must have exactly these events, in the same order.
     * @param webDriver the WebDriver to use
     * @param expectedEntries Array with expected Event entries.
     */
    public static void assertEntries(final WebDriver webDriver, final String... expectedEntries) {
        final List<String> actualEntries = AuditLogHelper.getEntries(webDriver);
        assertEquals("Unexpected elements found in table", Arrays.asList(expectedEntries), actualEntries);
    }
}
