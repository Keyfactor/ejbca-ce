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
import static org.junit.Assert.fail;

import java.util.Map;

import org.ejbca.webtest.util.WebTestUtil;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * 
 * Add End Entity helper class for EJBCA Web Tests.
 * 
 * @version $Id: AddEndEntityHelper.java 28852 2018-05-04 14:35:13Z oskareriksson $
 *
 */
public final class AddEndEntityHelper {

    private AddEndEntityHelper() {
        throw new AssertionError("Cannot instantiate class");
    }

    /**
     * Opens the 'Add End Entity' page.
     * 
     * @param webDriver the WebDriver to use
     * @param adminWebUrl the URL of the AdminWeb
     */
    public static void goTo(WebDriver webDriver, String adminWebUrl) {
        webDriver.get(adminWebUrl);
        webDriver.findElement(By.xpath("//li/a[contains(@href, 'addendentity.jsp')]")).click();
        assertEquals("Clicking 'Add End Entity' link did not redirect to expected page",
                WebTestUtil.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/ra/addendentity.jsp");
    }

    /**
     * Sets the End Entity's End Entity Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param eep the name of the End Entity Profile
     */
    public static void setEep(WebDriver webDriver, String eep) {
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectendentityprofile']")))).selectByVisibleText(eep);
    }

    /**
     * Sets the End Entity's Certificate Profile.
     * 
     * @param webDriver the WebDriver to use
     * @param cp the name of the Certificate Profile
     */
    public static void setCp(WebDriver webDriver, String cp) {
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcertificateprofile']")))).selectByVisibleText(cp);
    }

    /**
     * Sets the End Entity's CA.
     * 
     * @param webDriver the WebDriver to use
     * @param ca the name of the CA
     */
    public static void setCa(WebDriver webDriver, String ca) {
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectca']")))).selectByVisibleText(ca);
    }

    /**
     * Sets the End Entity's Token.
     * 
     * @param webDriver the WebDriver to use
     * @param token the name of the Token
     */
    public static void setToken(WebDriver webDriver, String token) {
        (new Select(webDriver.findElement(By.xpath("//select[@name='selecttoken']")))).selectByVisibleText(token);
    }

    /**
     * Sets fields when adding an End Entity.
     * 
     * Can only be used to set fields which contain a single text field,
     * e.g. 'Username' and 'CN, Common name'.
     * 
     * @param webDriver the WebDriver to use
     * @param fieldMap a map with {Key->Value} entries on the form {'Username'->'User123', 'CN, Common name'->'John Doe'}
     */
    public static void setFields(WebDriver webDriver, Map<String, String> fieldMap) {
        for (String key : fieldMap.keySet()) {
            // Find the text field input element which corresponds to this field's name
            WebElement fieldInput = webDriver.findElement(By.xpath("//td[descendant-or-self::*[text()='" + key + "']]/following-sibling::td//input[not(@type='checkbox')]"));
            fieldInput.sendKeys(fieldMap.get(key));
        }
    }

    /**
     * Clicks the 'Add' button, can also check that the operation was successful.
     * 
     * @param webDriver the WebDriver to use
     * @param eeName true if a check should be made that the operation was successful
     */
    public static void save(WebDriver webDriver, boolean assertSuccess) {
        String username = null;
        if (assertSuccess) {
            // Check the username of the End Entity
            username = webDriver.findElement(By.xpath("//td[descendant-or-self::*[text()='Username']]/following-sibling::td//input[not(@type='checkbox')]")).getAttribute("value");
        }

        // Click 'Add'
        webDriver.findElement(By.xpath("//input[@name='buttonadduser']")).click();

        if (assertSuccess) {
            // Check that the End Entity was added successfully
            try {
                // Check save message
                String saveMessage = webDriver.findElement(By.xpath("//div[@class='message info']")).getText();
                assertEquals("Unexpected message upon saving a new End Entity", "End Entity " + username + " added successfully.", saveMessage);

                // Check 'Previously added end entities' table
                String saveTable = webDriver.findElement(By.xpath("(//table[@class='results']//tr)[2]/td[1]")).getText();
                assertEquals("Unexpected username at top of 'Previously added end entities' table", username, saveTable);
            } catch (NoSuchElementException e) {
                fail("Could not find element upon adding an End Entity.");
            }
        }
    }
}
