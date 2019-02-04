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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * 
 * Add End Entity helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 *
 */
public class AddEndEntityHelper extends BaseHelper {

    private static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ra/addendentity.jsp";
        static final By PAGE_LINK = By.id("raAddendentity");
        static final By MESSAGE_INFO = By.xpath("//div[@class='message info']");
        static final By MESSAGE_ALERT = By.xpath("//div[@class='message alert']");
        
        // Input fields
        static final By INPUT_NAME_CONSTRAINTS_PERMITTED = By.xpath("//textarea[@name='textarencpermitted']");
        static final By INPUT_CERT_EXTENSION_DATA = By.xpath("//textarea[@name='textareaextensiondata']");
        static final By INPUT_EMAIL_NAME = By.xpath("//input[@name='textfieldemail']");
        static final By INPUT_EMAIL_DOMAIN = By.xpath("//input[@name='textfieldemaildomain']");
        
        // Select drop downs
        static final By SELECT_EEP = By.xpath("//select[@name='selectendentityprofile']");
        static final By SELECT_CP = By.xpath("//select[@name='selectcertificateprofile']");
        static final By SELECT_CA = By.xpath("//select[@name='selectca']");
        static final By SELECT_TOKEN = By.xpath("//select[@name='selecttoken']");
        static final By SELECT_REVOCATION_REASON = By.xpath("//select[@name='selectissuancerevocationreason']");
        static final By SELECT_NUMBER_OF_ALLOWED_REQUESTS = By.xpath("//select[@name='selectallowedrequests']");
        
        // Buttons
        static final By BUTTON_ADD_END_ENTITY = By.xpath("//input[@name='buttonadduser']");
        static final By BUTTON_RESET = By.xpath("//input[@name='Reset']");
        static final By BUTTON_KEY_RECOVERABLE = By.id("checkboxkeyrecoverable");
        static final By BUTTON_SEND_NOTIFICATIONS = By.id("checkboxsendnotification");
        
        static By getInputFieldLocatorByKey(final String key) {
            return By.xpath("//td[descendant-or-self::*[text()='" + key + "']]/following-sibling::td//input[not(@type='checkbox')]");
        }
    }
    
    public AddEndEntityHelper(WebDriver webDriver) {
        super(webDriver);
    }
    
    /**
     * Opens the 'Add end entity' page and asserts the correctness of URI path.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);;
    }

    /**
     * Selects End Entity Profile from the drop down.
     * 
     * @param eepName the name of the End Entity Profile
     */
    public void setEndEntityProfile(final String eepName) {
        selectOptionByName(Page.SELECT_EEP, eepName);
    }

    /**
     * Selects Certificate Profile from the drop down.
     * 
     * @param cpName the name of the Certificate Profile
     */
    public void setCertificateProfile(final String cpName) {
        selectOptionByName(Page.SELECT_CP, cpName);
    }

    /**
     * Selects Certificate Authority from the 'CA' drop down.
     * 
     * @param caName the name of the Certificate Authority
     */
    public void setCa(final String caName) {
        selectOptionByName(Page.SELECT_CA, caName);
    }

    /**
     * TODO Enum containing token types
     * 
     * Selects Token Tope from the 'Token' drop down.
     * 
     * @param tokenName - PEM, P12, JKS, User Generated etc.
     */
    public void setToken(final String tokenName) {
        selectOptionByName(Page.SELECT_TOKEN, tokenName);
    }

    /**
     * Clicks the check box 'Send Notifications'.
     */
    public void triggerSendNotifications() {
        clickLink(Page.BUTTON_SEND_NOTIFICATIONS);
    }
    
    /**
     * Sets fields when adding an End Entity.
     * 
     * Can only be used to set fields which contain a single text field,
     * e.g. 'Username' and 'CN, Common name'.
     * 
     * @param fieldMap a map with {Key->Value} entries on the form {'Username'->'User123', 'CN, Common name'->'John Doe'}
     */
    public void fillFields(final Map<String, String> fieldMap) {
        for (final String key : fieldMap.keySet()) {
            fillInput(Page.getInputFieldLocatorByKey(key), fieldMap.get(key));
        }
    }

    /**
     * Fills in the text field email and email domain
     * @param emailName e.g. 'john'
     * @param emailDomain e.g. 'company.com'
     */
    public void fillFieldEmail(final String emailName, final String emailDomain) {
        fillInput(Page.INPUT_EMAIL_NAME, emailName);
        fillInput(Page.INPUT_EMAIL_DOMAIN, emailDomain);
    }
    
    /**
     * Fills in the text area 'NameConstraintsPermitted'.
     * @param domains new line separated domains.
     */
    public void fillFieldNameConstraintsPermitted(String domains) {
        fillInput(Page.INPUT_NAME_CONSTRAINTS_PERMITTED, domains);
    }
    
    /**
     * Fills in the text area 'Extension Data'
     * @param data new line separated entries
     */
    public void fillFieldExtensionData(String data) {
        fillInput(Page.INPUT_CERT_EXTENSION_DATA, data);
    }
    
    /**
     * Asserts the given End Entity Profile is selected as first option 
     * @param expectedProfileName expected to be selected
     */
    public void assertEndEntityProfileSelected(final String expectedProfileName) {
        assertEquals("'" + expectedProfileName + "' was not selected as first option",
                expectedProfileName,
                getFirstSelectedOption(Page.SELECT_EEP));
    }
    
    /**
     * Asserts the given cert profile is selected as first option 
     * @param expectedProfileName expected to be selected
     */
    public void assertCertificateProfileSelected(final String expectedProfileName) {
        assertEquals("'" + expectedProfileName + "' was not selected as first option",
                expectedProfileName,
                getFirstSelectedOption(Page.SELECT_CP));
    }
    
    /**
     * Asserts the given token is selected as first option 
     * @param expectedToken expected to be selected
     */
    public void assertTokenSelected(final String expectedToken) {
        assertEquals("'" + expectedToken + "' was not selected as first option",
                expectedToken,
                getFirstSelectedOption(Page.SELECT_TOKEN));
    }
    
    /**
     * Asserts the given revocation reason is selected as first option 
     * @param expectedReason expected to be selected
     */
    public void assertRevocationReasonSelected(final String expectedReason) {
        assertEquals("'" + expectedReason + "' was not selected as first option",
                expectedReason,
                getFirstSelectedOption(Page.SELECT_REVOCATION_REASON));
    }
    
    /**
     * Verifies existence of 'Add' button on the page
     */
    public void assertAddEndEntityButtonExists() {
        assertElementExists(Page.BUTTON_ADD_END_ENTITY, "'Add' button was not found on 'Add End Entity' page");
    }
    
    /**
     * Verifies existence of 'Reset' button on the page
     */
    public void assertResetButtonExists() {
        assertElementExists(Page.BUTTON_RESET, "'Reset' button was not found on 'Add End Entity' page");
    }
    
    /**
     * Asserts all of the given text fields are rendered on the page.
     * @param fieldMap a map with {Key->Value} entries on the form {'Username'->'User123', 'CN, Common name'->'John Doe'}
     */
    public void assertFieldsExists(final Map<String, String> fieldMap) {
        for (final String key : fieldMap.keySet()) {
            assertElementExists(Page.getInputFieldLocatorByKey(key), 
                    "The input field '" + key + "' was not found on the 'Add End Entity Page'");
        }
    }
    
    /**
     * Asserts the text area 'Name Constraints, Permitted' is rendered on the page.
     */
    public void assertFieldNameConstraintsPermittedExists() {
        assertElementExists(Page.INPUT_NAME_CONSTRAINTS_PERMITTED, 
                "The text area 'Name Constraints, Permitted' did not exist");
    }
    
    /**
     * Asserts the text area 'Certificate Extension Data' is rendered on the page.
     */
    public void assertFieldCertExtensionDataExists() {
        assertElementExists(Page.INPUT_CERT_EXTENSION_DATA, 
                "The text area 'Certificate Extension Data, Permitted' did not exist");
    }
    
    /**
     * Asserts the correct info message is displayed after adding end entity
     * 
     * @param endEntityName name of the end entity expected to have been added
     */
    public void assertEndEntityAddedMessageDisplayed(final String endEntityName) {
        assertEquals("Unexpected info message while adding end entity",
                "End Entity " + endEntityName + " added successfully.",
                getElementText(Page.MESSAGE_INFO));
    }

    /**
     * Asserts the correct alert message is displayed after adding an end entity.
     */
    public void assertEndEntityAlertMessageDisplayed() {
        assertEquals("Unexpected info message while saving end entity",
                "Request has been sent for approval.",
                getElementText(Page.MESSAGE_ALERT));
    }

    /**
     * Asserts the given number of allowed requests is selected as first option 
     * @param expectedNumber to be selected
     */
    public void assertNumberOfAllowedRequestsSelected(final String expectedNumber) {
        assertEquals("'" + expectedNumber + "' was not selected as first option",
                expectedNumber,
                getFirstSelectedOption(Page.SELECT_NUMBER_OF_ALLOWED_REQUESTS));
    }
    
    /**
     * Assert whether 'Key Recoverable' check box should be enabled or disabled
     * @param assertEnabled if the check box is expected to be enabled
     */
    public void assertKeyRecoveryEnabled(final boolean assertEnabled) {
        if (assertEnabled) {
            assertTrue("'Key Recoverable' button was expected to be enabled", isEnabledElement(Page.BUTTON_KEY_RECOVERABLE));
        } else {
            assertFalse("'Key Recoverable' button was expected to be disabled", isEnabledElement(Page.BUTTON_KEY_RECOVERABLE));
        }

    }
    
    /**
     * Clicks the 'Add' button
     */
    public void addEndEntity() {
        clickLink(Page.BUTTON_ADD_END_ENTITY);
    }
}
