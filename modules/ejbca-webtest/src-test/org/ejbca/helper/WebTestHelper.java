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

package org.ejbca.helper;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.openqa.selenium.Alert;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;

/**
 * Helper class containing miscellaneous operations for EJBCA Web Tests.
 * 
 * @version $Id$
 */
public final class WebTestHelper {

    private WebTestHelper() {}

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
}