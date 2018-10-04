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
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Date;
import java.util.List;

import org.cesecore.util.ValidityDate;
import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * Audit Log helper class for EJBCA Web Tests.
 * 
 * Always reset filterTime before using the methods in this class, which makes sure
 * there only exists entries in the Audit Log for the test step currently executing.
 * 
 * @version $Id: AuditLogHelper.java 28911 2018-05-11 06:48:28Z oskareriksson $
 */
public final class AuditLogHelper {

    // Used to filter the Audit Log, only Audit Log entries after this time will be displayed
    private static String filterTime;
    static { resetFilterTime(); }

    private AuditLogHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /**
     * Resets the time to filter the Audit Log with. Only entries after the
     * last call of this method will be displayed in the Audit Log.
     */
    public static void resetFilterTime() {
        filterTime = ValidityDate.formatAsISO8601(new Date(), ValidityDate.TIMEZONE_SERVER);
    }

    /**
     * Opens the 'Audit Log' page, sets the conditions:
     * - [Event] [Not equals] [Access Control]
     * - [Time] [Greater than] [filterTime]
     * and then reloads the Audit Log.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
        // Open the Audit Log page
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href, 'audit/search.jsf')]")).click();
        assertEquals("Clicking 'View Log' link did not redirect to expected page",
                WebTestUtil.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/audit/search.jsf");

        // Set conditions
        clearConditions(webDriver);
        addCondition(webDriver, "Event", "Not equals", "Access Control");
        addCondition(webDriver, "Time", "Greater than", filterTime);

        // Set 'Displaying results' and 'Entries per page' to standard values
        setDisplayingResults(webDriver, 1);
        setEntriesPerPage(webDriver, 40);
        reload(webDriver);
    }

    /**
     * Asserts that a specific entry exists in the Audit Log.
     * 
     * @param webDriver the WebDriver to use
     * @param event the event to assert, e.g. "Certificate Profile Edit"
     * @param outcome the expected outcome, e.g. "Success" (or null to skip check)
     * @param ca the expected Certificate Authority, e.g. "ManagementCA" (or null to skip check)
     * @param details a list of strings which all should exist in the 'Details' field (order doesn't matter),
     *                e.g. ["Edited certificateprofile", "added:usecustomdnorderldap=false"] (or null to skip check)
     */
    public static void assertEntry(WebDriver webDriver, String event, String outcome, String ca, List<String> details) {
        try {
            // Find the row which has the event parameter as its 'Event' value
            WebElement row = webDriver.findElement(By.xpath("//tr[td[2]/text()='" + event + "']"));
            if (outcome != null) {
                // Assert expected value of 'Outcome' field
                assertEquals("Unexpected outcome for event " + event,
                        outcome, row.findElement(By.xpath("td[3]")).getText());
            }
            if (ca != null) {
                // Assert expected value of 'Certificate Authority' field
                assertEquals("Unexpected CA for event " + event,
                        ca, row.findElement(By.xpath("td[6]")).getText());
            }
            if (details != null) {
                // Extract value of 'Details' field, it is either a td element with text as its value
                // or a nested span element with text as its 'title' attribute
                WebElement detailsElement = row.findElement(By.xpath("(td[10]|td[10]/a/span)"));
                String detailsValue = "";
                if (detailsElement.getTagName().equals("td")) {
                    // Get value if it's a td element
                    detailsValue = detailsElement.getText();
                } else {
                    // Get attribute 'title' if it's a span element
                    detailsValue = detailsElement.getAttribute("title");
                }
                // Assert that all detail substrings exists in 'Details' field
                for (String detail : details) {
                    assertTrue("An expected detail didn't exist in the 'Details' field: " + detail,
                            detailsValue.contains(detail));
                }
            }
        } catch (NoSuchElementException e) {
            fail("The event " + event + " was not found in the Audit Log");
        }
    }

    /**
     * Adds a condition for filtering the Audit Log.
     * 
     * Different values for 'Column' either results in a drop-down or a
     * text field for 'Value', which the method handles automatically.
     * 
     * @param webDriver the WebDriver to use
     * @param column which Column to select
     * @param condition which Condition to select
     * @param value which Value to select (if drop-down) or input (if text field)
     */
    public static void addCondition(WebDriver webDriver, String column, String condition, String value) {
        // Set 'Column'
        Select columnSelect = new Select(webDriver.findElement(By.xpath("//select[contains(@id, 'conditionColumn')]")));
        columnSelect.selectByVisibleText(column);
        webDriver.findElement(By.xpath("//input[contains(@value, 'Add...') and @type='submit']")).click();

        // Set 'Condition'
        Select conditionSelect = new Select(webDriver.findElement(By.xpath("//td[text()='" + column + "']/following-sibling::td[1]/select")));
        conditionSelect.selectByVisibleText(condition);

        // Set 'Value'
        WebElement valueElement = webDriver.findElement(By.xpath("//td[text()='" + column + "']/following-sibling::td[2]/*"));
        if (valueElement.getTagName().equals("select")) {
            // If drop-down, select the correct value
            Select valueSelect = new Select(valueElement);
            valueSelect.selectByVisibleText(value);
        } else {
            // If text field, input the correct value
            valueElement.clear();
            valueElement.sendKeys(value);
        }

        // Apply the condition
        webDriver.findElement(By.xpath("//input[contains(@src, 'success') and @type='image']")).click();
    }

    /**
     * Sets the 'Displaying results' field.
     * 
     * @param webDriver the WebDriver to use
     * @param displayingResults the number to be entered
     */
    public static void setDisplayingResults(WebDriver webDriver, int displayingResults) {
        WebElement input = webDriver.findElement(By.id("search2:startIndex2"));
        input.clear();
        input.sendKeys(Integer.toString(displayingResults));
    }

    /**
     * Sets the 'Entries per page' field.
     * 
     * @param webDriver the WebDriver to use
     * @param entriesPerPage the number to be entered
     */
    public static void setEntriesPerPage(WebDriver webDriver, int entriesPerPage) {
        WebElement input = webDriver.findElement(By.id("search2:maxResults"));
        input.clear();
        input.sendKeys(Integer.toString(entriesPerPage));
    }

    /**
     * Returns the number of entries currently displayed in the Audit Log.
     * 
     * @param webDriver the WebDriver to use
     */
    public static int entryCount(WebDriver webDriver) {
        return webDriver.findElements(By.xpath("//table[caption[text()='Search results']]/tbody/tr")).size();
    }

    /**
     * Clicks the 'Clear all conditions' button, or does nothing if conditions
     * already cleared.
     * 
     * @param webDriver the WebDriver to use
     */
    public static void clearConditions(WebDriver webDriver) {
        try {
            webDriver.findElement(By.xpath("//input[contains(@value, 'Clear all conditions') and @type='submit']")).click();
        } catch (NoSuchElementException e) {
            // Do nothing if conditions already cleared
        }
    }

    /**
     * Clicks the 'Reload' button on the 'Audit Log' page.
     * 
     * @param webDriver the WebDriver to use
     */
    public static void reload(WebDriver webDriver) {
        webDriver.findElement(By.xpath("//input[@class='commandLink reload']")).click();
    }
}