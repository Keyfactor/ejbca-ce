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

import java.util.List;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

// TODO Replace this with BaseHelper
/**
 * Helper class containing miscellaneous operations for EJBCA Web Tests.
 * 
 * @version $Id: WebTestHelper.java 28852 2018-05-04 14:35:13Z oskareriksson $
 */
public final class WebTestHelper {

    private WebTestHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /**
     * Used to assert that there was an alert, and optionally if there was a
     * specific alert message.
     * 
     * @param webDriver the WebDriver to use
     * @param expectedMessage the expected message from the alert (or null for no assertion)
     * @param accept true if the alert should be accepted, false if it should be dismissed
     */
    public static void assertAlert(WebDriver webDriver, String expectedMessage, boolean accept) {
        Boolean alertExists = true;
        try {
            Alert alert = webDriver.switchTo().alert();
            // Assert that the correct alert message is displayed (if not null)
            if (expectedMessage != null) {
                assertEquals("Unexpected alert message: " + alert.getText(), expectedMessage, alert.getText());
            }
            // Accept or dismiss the alert message
            if (accept) {
                alert.accept();
            } else {
                alert.dismiss();
            }
            webDriver.switchTo().defaultContent();
        } catch (NoAlertPresentException e) {
            // No alert found
            alertExists = false;
        }
        assertTrue("Expected an alert but there was none", alertExists);
    }

    // TODO Replace with BaseHelper.selectOptionsByName()
    /**
     * Selects options by name in a Select element.
     * 
     * @param select the Select element
     * @param options the options to be selected (strings with the visible names) 
     */
    public static void selectOptions(Select select, List<String> options) {
        select.deselectAll();
        for (String option : options) {
            select.selectByVisibleText(option);
            // Assert that there is a selected option with the name
            boolean isSelected = false;
            for (WebElement selected : select.getAllSelectedOptions()) {
                if (selected.getText().equals(option)) {
                    isSelected = true;
                }
            }
            assertTrue("The option " + option + " was not found", isSelected);
        }
    }

}