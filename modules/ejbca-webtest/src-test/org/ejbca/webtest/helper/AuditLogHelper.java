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
        //
        configureFilteredView();
    }

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
        if(isInputElement(valueElementReference)) {
            fillInput(valueElementReference, columnValue);
        }
        // If drop-down, select the correct value
        if(isSelectElement(valueElementReference)) {
            selectOptionByName(valueElementReference, columnValue);
        }
        // Apply the condition
        clickLink(Page.BUTTON_APPLY_FILTERING_CONDITION);
    }

    /**
     * Sets the 'Displaying results' field.
     * Sets the 'Entries per page' field.
     */
    public void setViewPaginationProperties(final int displayStartPositionNr, final int nrOfResultsPerPage) {
        fillInput(Page.INPUT_DISPLAY_START_POSITION, "" + displayStartPositionNr);
        fillInput(Page.INPUT_NR_OF_RESULTS_PER_PAGE, "" + nrOfResultsPerPage);
    }

    public void reloadView() {
        clickLink(Page.BUTTON_RELOAD_VIEW);
    }

    public void assertLogEntryByEventText(
            final String eventText,
            final String outcomeText,
            final String certificateAuthorityText,
            final List<String> detailsList
    ) {

        // Find the row which has the event parameter as its 'Event' value
        final WebElement eventRowWebElement = findElement(Page.getEventLogRowByEventText(eventText));
        assertNotNull("The event [" + eventText + "] was not found in the Audit Log", eventRowWebElement);
        // Assert expected value of 'Outcome' field
        if(outcomeText != null) {
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

    //==================================================================================================================
    // TODO Refactor remaining
    //==================================================================================================================

    /**
     * Returns the number of entries currently displayed in the Audit Log.
     * 
     * @param webDriver the WebDriver to use
     */
    public static int entryCount(WebDriver webDriver) {
        return webDriver.findElements(By.xpath("//table[caption[text()='Search results']]/tbody/tr")).size();
    }

}