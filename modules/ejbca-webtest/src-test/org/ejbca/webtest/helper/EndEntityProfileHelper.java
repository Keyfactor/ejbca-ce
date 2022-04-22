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
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * End Entity Profile helper class for EJBCA Web Tests.
 *
 * @version $Id$
 */
public class EndEntityProfileHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'End Entity Profiles' page.
     */
    private static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ra/editendentityprofiles/editendentityprofiles.xhtml";
        static final By PAGE_LINK = By.id("raEditendentityprofiles");
        // End Entity Profiles Form
        static final By INPUT_NAME = By.id("manageEndEntityProfiles:addProfileNew");
        static final By BUTTON_ADD = By.id("manageEndEntityProfiles:addButton");
        static final By BUTTON_EDIT = By.id("manageEndEntityProfiles:editButton");
        static final By BUTTON_CLONE = By.id("manageEndEntityProfiles:cloneButton");
        static final By BUTTON_RENAME = By.id("manageEndEntityProfiles:renameButton");
        static final By BUTTON_DELETE = By.id("manageEndEntityProfiles:deleteButton");
        static final By SELECT_EE_PROFILES = By.id("manageEndEntityProfiles:profilesListBox");
        //modal block
        static final By MODAL_BLOCK_CONTAINER = By.id("modalBlockContainer");
        static final By CONFIRM_DELETE_BUTTON = By.id("modal:deleteConfirmButton");
        static final By CANCEL_DELETE_BUTTON = By.id("modal:deleteCancelButton");

        // End Entity Profile Form
        static final By TEXT_TITLE_END_ENTITY_PROFILE = By.xpath("//div/h3");
        static final By INPUT_USERNAME_AUTO_GENERATED = By.id("eeProfiles:autoGenerateUserNameCheckBox");
        static final By INPUT_USE_ISSUANNCE_REVOCATION_REASON = By.id("eeProfiles:useRevocationReasonAfterIssuanceCheckBox");
        // Use only the domain part of the address, without the '@' character
        static final By INPUT_USE_END_ENTITY_EMAIL = By.id("eeProfiles:emailCheckBox");
        // Maximum number of failed login attempts / Use
        static final By INPUT_USE_MAX_FAILED_LOGINS = By.id("eeProfiles:nrFailedAttempts");
        // Batch generation / Use
        static final By INPUT_BATCH_GENERATION = By.id("eeProfiles:batchCheckBox");
        // Other certificate data / Custom certificate serial number in hex / Use
        static final By INPUT_CUSTOM_SERIAL_NUMBER = By.id("eeProfiles:certSerialNumberCheckBox");
        // Other certificate data / Certificate Validity Start Time /Use
        static final By INPUT_USE_START_TIME = By.id("eeProfiles:certValidityStartTimeCheckBox");
        // Other certificate data / Certificate Validity End Time /Use
        static final By INPUT_USE_END_TIME = By.id("eeProfiles:certValidityEndTimeCheckBox");
        // Other certificate data / Certificate Validity Start Time /Value
        static final By INPUT_START_TIME = By.id("eeProfiles:textFieldCertValidityStartTime");
        // Other certificate data / Certificate Validity END Time /Value
        static final By INPUT_END_TIME = By.id("eeProfiles:textFieldCertValidityEndTime");
        // Other certificate data / Certificate Validity Start Time / Modifiable
        static final By INPUT_START_TIME_MODIFIABLE = By.id("eeProfiles:certValidityStartTimeModCheckBox");
        // Other certificate data / Certificate Validity END Time / Modifiable
        static final By INPUT_END_TIME_MODIFIABLE = By.id("eeProfiles:certValidityEndTimeModCheckBox");
        //Other certificate data/ Name Constraints, Permitted / Use
        static final By INPUT_USE_NAME_CONSTRAINTS = By.id("eeProfiles:nameConstraintsPermittedCheckBox");
        // Other certificate data/ Custom certificate extension data
        static final By INPUT_USE_EXTENSION_DATA = By.id("eeProfiles:useCustomCertificateExtensionDataCheckBox");
        // Other Data / Number of allowed requests / Use
        static final By INPUT_USE_NUMBER_OF_ALLOWED_REQUESTS = By.id("eeProfiles:numberOfAllowedRequestsCheckBox");
        // Other Data / Key Recoverable / Use
        static final By INPUT_USE_KEY_RECOVERABLE = By.id("eeProfiles:keyRecoverableCheckBox");
        // Other Data / Revocation reason to set after certificate issuance /Use
        static final By INPUT_USE_ISSUANCE_REVOCATION_REASON = By.id("eeProfiles:useRevocationReasonAfterIssuanceCheckBox");
        // Other Data / Send Notification  / Use
        static final By INPUT_USE_SEND_NOTIFICATION = By.id("eeProfiles:sendNotificationCheckBox");
        // Other Data / Send Notification  / Default
        static final By INPUT_DEFAULT_SEND_NOTIFICATION = By.id("eeProfiles:sendNotificationDefaultCheckBox");
        // Other Data / Send Notification  / Required
        static final By INPUT_REQUIRED_SEND_NOTIFICATION = By.id("eeProfiles:sendNotificationRequiredCheckBox");
        static final By SELECT_DEFAULT_CERTIFICATE_PROFILE = By.id("eeProfiles:defaultCertificateProfile");
        static final By SELECT_AVAILABLE_CERTIFICATE_PROFILES = By.id("eeProfiles:availableCertProfiles");
        static final By SELECT_ISSUANCE_REVOCATION_REASON = By.id("eeProfiles:revocationReasonMenu");
        static final By SELECT_DEFAULT_CP = By.id("eeProfiles:defaultCertificateProfile");
        static final By SELECT_DEFAULT_CA = By.id("eeProfiles:defaultCAMenu");
        static final By SELECT_AVAILABLE_CAS = By.id("eeProfiles:availableCA");
        static final By SELECT_DEFAULT_TOKEN = By.id("eeProfiles:defaultTokenMenu");
        static final By SELECT_AVAILABLE_TOKENS = By.id("eeProfiles:availableToken");

        static final By SELECT_SUBJECT_DN_ATTRS = By.id("eeProfiles:subjectDnAttributeType");
        static final By SELECT_SUBJECT_ALTERNATIVE_NAME = By.id("eeProfiles:subjectAltNameAttributeType");
        static final By NOTIFICATION = By.xpath("//tr[td/strong[text()='Send Notification']]/following-sibling::tr[1]/td[2][contains(text(), 'Notification')]");
        // Other Data / Send Notification  / Add
        static final By BUTTON_ADD_NOTIFICATION = By.id("eeProfiles:addButton");
        static final By CONTAINER_NOTIFICATION_FORM = By.id("eeProfiles:userNotificationsWrapper");
        static final By BUTTON_ADD_SUBJECT_ALT_NAME = By.id("eeProfiles:addSubjectAltNameAttributeButton");
        static final By BUTTON_ADD_SUBJECT_DN_NAME = By.id("eeProfiles:addSubjectDnAttributeButton");
        // Other Data / Send Notification  / Delete all
        static final By BUTTON_DELETE_ALL_NOTIFICATION = By.id("eeProfiles:sendNotificationsDeleteAllButton");

        static final By BUTTON_SAVE_PROFILE = By.id("eeProfiles:saveButton");
        static final By BUTTON_CANCEL_EDITING_PROFILE = By.id("eeProfiles:cancelButton");
        static final By BUTTON_BACK_TO_END_ENTITY_PROFILES = By.xpath("//td/a[contains(@href,'editendentityprofiles.xhtml')]");

        // Dynamic references
        static By getEEPOptionContainingText(final String text) {
            return By.xpath("//option[text()='" + text + "']");
        }

        static By getSubjectAttributesSelectByAttributeType(final String attributeType) {
            return By.id("eeProfiles:subject" + StringUtils.capitalize(attributeType) + "AttributeType");
        }

        static By getSubjectAttributesAddButtonByAttributeType(final String attributeType) {
            return By.id("eeProfiles:addSubject" + StringUtils.capitalize(attributeType) + "AttributeButton");
        }

        static By getSubjectAttributesAttributeByAttributeName(final String attributeName) {
            return By.xpath("//label[contains(text(), '" + attributeName + "')]");
        }

        static By getSubjectAttributesAttributeModifiableByAttributeTypeAndAttributeIndex(final String attributeType, final int attributeIndex) {
            return By.id("eeProfiles:subject" + StringUtils.capitalize(attributeType) + "Components:" + attributeIndex + ":" + attributeType + "ModifiableCheckBox");
        }

        static By getSubjectAttributesAttributeTextfieldByAttributeTypeAndAttributeIndex(final String attributeType, final int attributeIndex) {
            String capitalizedAttributeType = StringUtils.capitalize(attributeType);
            return By.id("eeProfiles:subject" + capitalizedAttributeType + "Components:" + attributeIndex + ":subject" + capitalizedAttributeType + "TextField");
        }

        // Other Data / Send Notification  / Delete
        static By getDeleteNotificationButtonByIndex(final int index) {
            return By.xpath("//input[contains(@id, ':" + index + ":removeSendNotificationButton')]");
        }

        // Other Data / Send Notification  / Notification Sender
        static By getNotificationSenderByIndex(final int index) {
            return By.xpath("//input[contains(@id, ':" + index + ":textFieldNotificationSender')]");
        }

        // Other Data / Send Notification  / Notification Subject
        static By getNotificationSubjectByIndex(final int index) {
            return By.xpath("//input[contains(@id, ':" + index + ":textFieldNotificationSubject')]");
        }

        // Other Data / Send Notification  / Notification Recipient
        static By getNotificationRecipientByIndex(final int index) {
            return By.xpath("//input[contains(@id, ':" + index + ":textFieldNotificationRecipient')]");
        }

        // Other Data / Send Notification / Notification Events
        static By getNotificationEventsByIndex(final int index) {
            return By.xpath("//select[contains(@id, ':" + index + ":notificationEventsListbox')]");
        }

        // Other Data / Send Notification / Notification Message
        static By getNotificationMessageByIndex(final int index) {
            return By.xpath("//textarea[contains(@id, ':" + index + ":textAreaNotificationMessage')]");
        }

        // Subject DN Attributes checkboxes
        static By getSubjectDnAttributesCheckBox(final String dnAttributeName, final String checkboxName) {
            return By.xpath("//td/label[contains(text(),'" + dnAttributeName + "')]/../following-sibling::td//input[contains(@id,'" + checkboxName + "CheckBox')]");
        }
    }

    public EndEntityProfileHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'End Entity Profiles' page and asserts the correctness of URI path.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Asserts the current URI equals to End Entity Profile page URI.
     */
    public void assertIsOnStartPage() {
        assertPageUri(Page.PAGE_URI);
    }

    /**
     * Adds a new End Entity Profile, and asserts that it appears in End Entities Profiles table.
     *
     * @param endEntityProfileName an End Entity Profile name.
     */
    public void addEndEntityProfile(final String endEntityProfileName) {
        fillInput(Page.INPUT_NAME, endEntityProfileName);
        clickLink(Page.BUTTON_ADD);
        assertEndEntityProfileNameExists(endEntityProfileName);
    }

    /**
     * Opens the edit page for an End Entity Profile, then asserts that the correct End Entity Profile is being edited.
     *
     * @param endEntityProfileName an End Entity Profile name.
     */
    public void openEditEndEntityProfilePage(final String endEntityProfileName) {
        selectOptionByName(Page.SELECT_EE_PROFILES, endEntityProfileName);
        clickLink(Page.BUTTON_EDIT);
        assertEndEntityProfileTitleExists(endEntityProfileName);
    }

    /**
     * Edits the End Entity Profile
     *
     * @param defaultCertificateProfileName the value for 'Default Certificate Profile'.
     * @param selectedCertificateProfiles   the list for 'Available Certificate Profiles' selector.
     * @param defaultCAName                 the value for 'Default CA'.
     * @param selectedCAs                   the list for 'Available CAs' selector.
     */
    public void editEndEntityProfile(
            final String defaultCertificateProfileName,
            final List<String> selectedCertificateProfiles,
            final String defaultCAName,
            final List<String> selectedCAs
    ) {
        selectOptionByName(Page.SELECT_DEFAULT_CERTIFICATE_PROFILE, defaultCertificateProfileName);
        deselectOptions(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES);
        selectOptionsByName(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES, selectedCertificateProfiles);
        selectDefaultCa(defaultCAName);
        deselectOptions(Page.SELECT_AVAILABLE_CAS);
        selectOptionsByName(Page.SELECT_AVAILABLE_CAS, selectedCAs);
    }

    /**
     * Selects the default certification profile
     *
     * @param defaultCPName default Certificate Profile name.
     */

    public void selectDefaultCp(String defaultCPName) {
        selectOptionByName(Page.SELECT_DEFAULT_CP, defaultCPName);
    }

    /**
     * Selects Available CAs by single name.
     *
     * @param caName Certificate Profile name.
     */
    public void selectAvailableCa(String caName) {
        deselectOptions(Page.SELECT_AVAILABLE_CAS);
        selectOptionsByName(Page.SELECT_AVAILABLE_CAS, Collections.singletonList(caName));
    }

    /**
     * Selects Available Certificate Profiles.
     *
     * @param cPNames Certificate Profile names.
     */
    public void selectAvailableCps(String... cPNames) {
        deselectOptions(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES);
        selectOptionsByName(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES, Arrays.asList(cPNames));
    }

    /**
     * Sets a value for default CA
     *
     * @param defaultCAName а name of default CA to be selected
     */
    public void selectDefaultCa(String defaultCAName) {
        selectOptionByName(Page.SELECT_DEFAULT_CA, defaultCAName);
    }

    /**
     * Selects Available Certificate Profiles by single name.
     *
     * @param cPName Certificate Profile name.
     */
    public void selectAvailableCp(String cPName) {
        deselectOptions(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES);
        selectOptionsByName(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES, Collections.singletonList(cPName));
    }
    /**
     * Saves the End Entity Profile with success assertion.
     */
    public void saveEndEntityProfile() {
        saveEndEntityProfile(true);
    }

    /**
     * Saves the End Entity Profile with assertion.
     *
     * @param withAssertion true for success assertion, false otherwise.
     */
    public void saveEndEntityProfile(final boolean withAssertion) {
        clickLink(Page.BUTTON_SAVE_PROFILE);
        if (withAssertion) {
            assertInfoMessageAppears("End Entity Profile '.*' saved\\.",
                    "End Entity Profile save message was not found.",
                    "Expected profile save message was not displayed");
        }
    }
    
    /** Saves the End Entity Profile with failure assertion. */
    public void saveEndEntityProfileWithClientSideErrors() {
        saveEndEntityProfile(false);
        assertIsOnEditPage();
    }

    /** Fails test if not on Edit page (e.g. on list page) */
    private void assertIsOnEditPage() {
        final WebElement endEntityProfileTitle = findElement(Page.TEXT_TITLE_END_ENTITY_PROFILE);
        if (endEntityProfileTitle == null) {
            fail("Should stay on the edit page for the end entity profile.");
        }
    }

    /**
     * Clones the End Entity Profile.
     *
     * @param endEntityProfileName    source End Entity Profile name.
     * @param newEndEntityProfileName target End Entity Profile name.
     */
    public void cloneEndEntityProfile(final String endEntityProfileName, final String newEndEntityProfileName) {
        // Select End Entity Profile in list
        selectOptionByName(Page.SELECT_EE_PROFILES, endEntityProfileName);
        // Clone the End Entity Profile
        fillInput(Page.INPUT_NAME, newEndEntityProfileName);
        clickLink(Page.BUTTON_CLONE);
    }

    /**
     * Renames the End Entity Profile.
     *
     * @param oldEndEntityProfileName source End Entity Profile name.
     * @param newEndEntityProfileName target End Entity Profile name.
     */
    public void renameEndEntityProfile(final String oldEndEntityProfileName, final String newEndEntityProfileName) {
        // Select End Entity Profile in list
        selectOptionByName(Page.SELECT_EE_PROFILES, oldEndEntityProfileName);
        // Rename the End Entity Profile
        fillInput(Page.INPUT_NAME, newEndEntityProfileName);
        clickLink(Page.BUTTON_RENAME);
    }

    /**
     * Calls the delete dialog of the End Entity Profile by name.
     *
     * @param endEntityProfileName End Entity Profile name.
     */
    public void deleteEndEntityProfile(final String endEntityProfileName) {
        // Select End Entity Profile in list
        selectOptionByName(Page.SELECT_EE_PROFILES, endEntityProfileName);
        clickLink(Page.BUTTON_DELETE);
    }

    /**
     * Confirms/Discards the deletion of End Entity Profile with expected message.
     *
     * @param isConfirmed true to confirm deletion, false otherwise.
     */
    public void confirmEndEntityProfileDeletion(final boolean isConfirmed) {
        WebElement modalContainer = findElement(Page.MODAL_BLOCK_CONTAINER);
        assertNotNull("Confirmation modal block on End Entity Profile delete is not present", modalContainer);
        if (isConfirmed) {
            clickLink(Page.CONFIRM_DELETE_BUTTON);
        } else {
            clickLink(Page.CANCEL_DELETE_BUTTON);
        }
    }

    /**
     * Asserts the End Entity Profile name exists in the list of End Entity Profiles.
     *
     * @param endEntityProfileName End Entity Profile name.
     */
    public void assertEndEntityProfileNameExists(final String endEntityProfileName) {
        final WebElement selectWebElement = findElement(Page.SELECT_EE_PROFILES);
        if (findElement(selectWebElement, Page.getEEPOptionContainingText(endEntityProfileName)) == null) {
            fail(endEntityProfileName + " was not found in the List of End Entity Profiles.");
        }
    }

    /**
     * Asserts the End Entity Profile name does not exist in the list of End Entity Profiles.
     *
     * @param endEntityProfileName End Entity Profile name.
     */
    public void assertEndEntityProfileNameDoesNotExist(final String endEntityProfileName) {
        final WebElement selectWebElement = findElement(Page.SELECT_EE_PROFILES);
        if (findElement(selectWebElement, Page.getEEPOptionContainingText(endEntityProfileName), false) != null) {
            fail(endEntityProfileName + " was found in the List of End Entity Profiles.");
        }
    }

    /**
     * Triggers the checkbox 'Username' Auto-generated.
     */
    public void triggerUsernameAutoGenerated() {
        clickLink(Page.INPUT_USERNAME_AUTO_GENERATED);
    }

    /**
     * Triggers the checkbox 'Revocation reason to set after certificate issuance'
     */
    public void triggerRevocationReasonSetAfterCertIssuance() {
        clickLink(Page.INPUT_USE_ISSUANNCE_REVOCATION_REASON);
    }

    /**
     * Triggers the checkbox 'Use' for 'Maximum number of failed login attempts '.
     */
    public void triggerMaximumNumberOfFailedLoginAttempts() {
        clickLink(Page.INPUT_USE_MAX_FAILED_LOGINS);
    }

    /**
     * Triggers the checkbox 'Use' for 'Certificate Validity Start Time'.
     */
    public void triggerCertificateValidityStartTime() {
        clickLink(Page.INPUT_USE_START_TIME);
    }
    
    /** Sets the 'Use' checkbox for 'Certificate Validity Start Time' to the given state. */
    public void setUseCertificateValidityStartTime(final boolean use) {
        if (isSelectedElement(Page.INPUT_USE_START_TIME) != use) {
            triggerCertificateValidityStartTime();
        }
    }

    /**
     * Triggers the checkbox 'Use' for 'Certificate Validity End Time'.
     */
    public void triggerCertificateValidityEndTime() {
        clickLink(Page.INPUT_USE_END_TIME);
    }

    /** Sets the 'Use' checkbox for 'Certificate Validity End Time' to the given state. */
    public void setUseCertificateValidityEndTime(final boolean use) {
        if (isSelectedElement(Page.INPUT_USE_END_TIME) != use) {
            triggerCertificateValidityEndTime();
        }
    }
    
    /** Checks the state for the 'Use' checkbox for 'Custom Validity Start Time' */
    public void assertUseCustomValidityStartTimeIsSelected(boolean expectedState) {
        assertEquals("'Use' checkbox for 'Custom Validity Start Time' should be checked.", expectedState, isSelectedElement(Page.INPUT_USE_START_TIME));
    }
    
    /** Checks the state for the 'Use' checkbox for 'Custom Validity End Time' */
    public void assertUseCustomValidityEndTimeIsSelected(boolean expectedState) {
        assertEquals("'Use' checkbox for 'Custom Validity End Time' should be checked.", expectedState, isSelectedElement(Page.INPUT_USE_END_TIME));
    }
    
    /** Checks the state for the 'Use' checkbox for 'Custom Validity Start Time' */
    public void assertCustomValidityStartTimeModifiableIsSelected(boolean expectedState) {
        assertEquals("'Modifiable' checkbox for 'Custom Validity Start Time' should be checked.", expectedState, isSelectedElement(Page.INPUT_START_TIME_MODIFIABLE));
    }
    
    /** Checks the state for the 'Use' checkbox for 'Custom Validity End Time' */
    public void assertCustomValidityEndTimeModifiableIsSelected(boolean expectedState) {
        assertEquals("'Modifiable' checkbox for 'Custom Validity End Time' should be checked.", expectedState, isSelectedElement(Page.INPUT_END_TIME_MODIFIABLE));
    }
    
    /** Checks if the Custom Validity Start Time controls are enabled (true) or disabled (false) */
    public void assertCustomValidityStartTimeFieldsEnabled(boolean enabled) {
        assertEquals("'Custom Validity Start Time' text box had the wrong enabled state.", enabled, isEnabledElement(Page.INPUT_START_TIME));
        assertEquals("'Custom Validity Start Time' 'Modifiable' chekcbox had the wrong enabled state.", enabled, isEnabledElement(Page.INPUT_START_TIME_MODIFIABLE));
    }

    /** Checks if the Custom Validity End Time controls are enabled (true) or disabled (false) */
    public void assertCustomValidityEndTimeFieldsEnabled(boolean enabled) {
        assertEquals("'Custom Validity End Time' text box had the wrong enabled state.", enabled, isEnabledElement(Page.INPUT_END_TIME));
        assertEquals("'Custom Validity End Time' 'Modifiable' chekcbox had the wrong enabled state.", enabled, isEnabledElement(Page.INPUT_END_TIME_MODIFIABLE));
    }

    /**
     * Triggers the checkbox 'Use' for 'Name Constraints, Permitted'.
     */
    public void triggerNameConstraints() {
        clickLink(Page.INPUT_USE_NAME_CONSTRAINTS);
    }

    /**
     * Triggers the checkbox 'Use' for 'Custom certificate extension data'.
     */
    public void triggerExtensionData() {
        clickLink(Page.INPUT_USE_EXTENSION_DATA);
    }

    /**
     * Triggers the checkbox 'Use' for 'Number of allowed requests '.
     */
    public void triggerNumberOfAllowedRequests() {
        clickLink(Page.INPUT_USE_NUMBER_OF_ALLOWED_REQUESTS);
    }

    /**
     * Triggers the checkbox 'Use' for 'Key Recoverable'.
     */
    public void triggerKeyRecoverable() {
        clickLink(Page.INPUT_USE_KEY_RECOVERABLE);
    }

    /**
     * Triggers the checkbox 'Use' for 'Revocation reason to set after certificate issuance'.
     */
    public void triggerIssuanceRevocationReason() {
        clickLink(Page.INPUT_USE_ISSUANCE_REVOCATION_REASON);
    }

    /**
     * Add Notification.
     */
    public void addNotification() {
        clickLink(Page.BUTTON_ADD_NOTIFICATION);
        // Add a timeout to load notifications container after click
        findElement(Page.CONTAINER_NOTIFICATION_FORM);
    }

    /**
     * Delete All Notification.
     */
    public void deleteAllNotifications() {
        clickLink(Page.BUTTON_DELETE_ALL_NOTIFICATION);
    }

    /**
     * Delete Notification.
     *
     * @param buttonIndex the index of notification to be deleted
     */
    public void deleteNotification(final int buttonIndex) {
        clickLink(Page.getDeleteNotificationButtonByIndex(buttonIndex));
    }

    /**
     * Triggers the checkbox 'Use'and 'Default' for 'Send Notification'.
     */
    public void triggerSendNotification() {
        clickLink(Page.INPUT_USE_SEND_NOTIFICATION);
        clickLink(Page.INPUT_DEFAULT_SEND_NOTIFICATION);        
        // Add a timeout to load button 'Add' after click
        findElement(Page.BUTTON_ADD_NOTIFICATION);
    }

    /**
     * Fills  Certificate Validity Start Time
     */
    public void setCertificateValidityStartTime(String startTime) {
        fillInput(Page.INPUT_START_TIME, startTime);
    }

    /** Returns the current value in the 'Certificate Validity Start Time' text field */
    public String getCertificateValidityStartTime() {
        return getElementText(Page.INPUT_START_TIME);
    }

    /**
     * Fills  Certificate Validity End Time
     */
    public void setCertificateValidityEndTime(String endTime) {
        fillInput(Page.INPUT_END_TIME, endTime);
    }

    /** Returns the current value in the 'Certificate Validity End Time' text field */
    public String getCertificateValidityEndTime() {
        return getElementText(Page.INPUT_END_TIME);
    }

    /**
     * Fills Notification Sender
     *
     * @param inputIndex the index of notification to check
     */
    public void setNotificationSender(final int inputIndex, String sender) {
        fillInput(Page.getNotificationSenderByIndex(inputIndex), sender);
    }
    
    /**
     * Fills Notification Recipient
     *
     * @param inputIndex the index of notification to check
     */
    public void setNotificationRecipient(final int inputIndex, String recipient ) {
        fillInput(Page.getNotificationRecipientByIndex(inputIndex), recipient);
    }

    public void setSubjectAlternativeName(final String subjectAltName) {
        selectOptionByName(Page.SELECT_SUBJECT_ALTERNATIVE_NAME, subjectAltName);
        clickLink(Page.BUTTON_ADD_SUBJECT_ALT_NAME);
    }

    public void setSubjectDNName(final String subjectAltName) {
        selectOptionByName(Page.SELECT_SUBJECT_DN_ATTRS, subjectAltName);
        clickLink(Page.BUTTON_ADD_SUBJECT_DN_NAME);
    }

    /**
     * Fills Notification Subject
     * @param inputIndex the index of notification to check
     * @param subject notification subject
     */
    public void setNotificationSubject(final int inputIndex, final String subject) {
        fillInput(Page.getNotificationSubjectByIndex(inputIndex), subject);
    }

    /**
     * Fills Notification Message
     *
     * @param inputIndex the index of notification to check
     * @param message notification message
     */
    public void setNotificationMessage(final int inputIndex, String message) {
        fillInput(Page.getNotificationMessageByIndex(inputIndex), message);
    }

    /**
     * Fills Notification Message
     *
     * @param inputIndex the index of notification to check
     * @param text the text to inserted as notification sender, recipient, subject and message
     */
    public void fillNotification(final int inputIndex, String text) {
        setNotificationSender(inputIndex, text);
        fillInput(Page.getNotificationRecipientByIndex(inputIndex), text);
        setNotificationSubject(inputIndex, text);
        setNotificationMessage(inputIndex, text);
    }

    /**
     * Selects the desired issuance revocation reason from the 'Revocation reason to set after certificate issuance'
     * drop down menu.
     *
     * @param reason revocation reason. E.g. 'Suspended: Certificate hold'
     */
    public void setIssuanceRevocationReason(final String reason) {
        selectOptionByName(Page.SELECT_ISSUANCE_REVOCATION_REASON, reason);
    }

    /**
     * Asserts the element 'Username' Auto-generated is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertUsernameAutoGeneratedIsSelected(final boolean isSelected) {
        assertEquals(
                "'Username' Auto-generated field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_USERNAME_AUTO_GENERATED)
        );
    }

    /**
     * Asserts the element 'Use' in Send Notification is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertUseSendNotificationIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use' for 'Send Notification' isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_USE_SEND_NOTIFICATION)
        );
    }

    /**
     * Asserts the element 'Default' in Send Notification is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertDefaultSendNotificationIsSelected(final boolean isSelected) {
        assertEquals(
                "'Default' for 'Send Notification' isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_DEFAULT_SEND_NOTIFICATION)
        );
    }

    /**
     * Asserts the element 'Default' in Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDefaultSendNotificationIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Default' for 'Send Notification' isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_DEFAULT_SEND_NOTIFICATION)
        );
    }

    /**
     * Asserts the element 'Required' in Send Notification is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertRequiredSendNotificationIsSelected(final boolean isSelected) {
        assertEquals(
                "'Required' for 'Send Notification' isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_REQUIRED_SEND_NOTIFICATION)
        );
    }

    /**
     * Asserts the element 'Required' in Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertRequiredSendNotificationIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Required' for 'Send Notification' isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_REQUIRED_SEND_NOTIFICATION)
        );
    }

    /**
     * Asserts the button 'Cancel' Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertAddNotificationButtonIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Add notification' button for 'Send Notification' isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.BUTTON_ADD_NOTIFICATION)
        );
    }

    /**
     * Asserts the button 'Delete' Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDeleteNotificationButtonIsEnabled(final boolean isEnabled, final int buttonIndex) {
        assertEquals(
                "'Delete notification' button with index " + buttonIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getDeleteNotificationButtonByIndex(buttonIndex))
        );
    }

    /**
     * Asserts the input 'Notification Sender' in Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertNotificationSenderInputIsEnabled(final boolean isEnabled, final int buttonIndex) {
        assertEquals(
                "'Notification Sender' input text with index " + buttonIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getNotificationSenderByIndex(buttonIndex))
        );
    }

    /**
     * Asserts the 'Notification Subject' input is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationSubjectInputIsEnabled(final boolean isEnabled, final int inputIndex) {
        assertEquals(
                "'Notification Subject' input for field with index " + inputIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getNotificationSubjectByIndex(inputIndex))
        );
    }

    /**
     * Asserts the 'Notification Recipient' input is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationRecipientInputIsEnabled(final boolean isEnabled, final int inputIndex) {
        assertEquals(
                "'Notification Recipient' input for field with index " + inputIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getNotificationRecipientByIndex(inputIndex))
        );
    }

    /**
     * Asserts the 'Notification Events' select is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationEventsInputIsEnabled(final boolean isEnabled, final int inputIndex) {
        assertEquals(
                "'Notification Events' select for field with index " + inputIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getNotificationEventsByIndex(inputIndex))
        );
    }

    /**
     * Asserts the 'Notification Message' textarea is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationTextareaInputIsEnabled(final boolean isEnabled, final int inputIndex) {
        assertEquals(
                "'Notification Message' textarea for field with index " + inputIndex + " isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.getNotificationMessageByIndex(inputIndex))
        );
    }

    /**
     * Asserts the element 'Required' Send Notification is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDeleteAllNotificationButtonIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Delete All' button for 'Notification' isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.BUTTON_DELETE_ALL_NOTIFICATION)
        );
    }

    /**
     * Clicks the back link.
     */
    public void triggerBackToEndEntityProfiles() {
        clickLink(Page.BUTTON_BACK_TO_END_ENTITY_PROFILES);
    }

    /**
     * Adds an attribute to 'Subject DN Attributes', 'Subject Alternative Name' or
     * 'Subject Directory Attributes' while editing an End Entity Profile.
     *
     * @param attributeType either 'dn', 'altName' or 'directory'
     * @param attributeName the displayed name of the attribute, e.g. 'O, Organization'
     */
    private void addSubjectAttribute(final String attributeType, final String attributeName) {
        selectOptionByName(Page.getSubjectAttributesSelectByAttributeType(attributeType), attributeName);
        clickLink(Page.getSubjectAttributesAddButtonByAttributeType(attributeType));
    }
    
    /**
     * Adds an attribute to 'Subject DN Attributes'
     *
     * @param attributeName the displayed name of the attribute, e.g. 'O, Organization'
     */
    public void addSubjectDnAttribute(final String attributeName) {
        addSubjectAttribute("dn", attributeName);
    }
    
    /**
     * Adds an attribute to 'Subject Alternative Name'
     *
     * @param attributeName the displayed name of the attribute, e.g. 'DNS Name'
     */
    public void addSubjectAltNameAttribute(final String attributeName) {
        addSubjectAttribute("altName", attributeName);
    }

    /**
     * Adds an attribute to 'Subject Directory Attributes'
     *
     * @param attributeName the displayed name of the attribute, e.g. 'Date of birth (YYYYMMDD)'
     */
    public void addSubjectDirectoryAttribute(final String attributeName) {
        addSubjectAttribute("directory", attributeName);
    }

    /**
     * Asserts the attribute exists in the section 'Subject DN Attributes'.
     *
     * @param attributeName name of the attribute.
     */
    public void assertSubjectAttributeExists(final String attributeName) {
        final WebElement subjectAttributeWebElement = findElement(Page.getSubjectAttributesAttributeByAttributeName(attributeName));
        assertNotNull(
                "The attribute " + attributeName + " does not exist",
                subjectAttributeWebElement
        );
    }

    /**
     * Triggers the input 'Modifiable' for an attribute specified by its type and index in the section 'Subject DN Attributes'.
     *
     * @param attributeType  attribute's type.
     * @param attributeIndex attribute's index.
     */
    public void triggerSubjectAttributesAttributeModifiable(final String attributeType, final int attributeIndex) {
        clickLink(Page.getSubjectAttributesAttributeModifiableByAttributeTypeAndAttributeIndex(attributeType, attributeIndex));
    }

    /**
     * Asserts the appearance of error message with expected content
     *
     * @param expectedErrorMessage expected error message.
     */
    public void assertSubjectAttributesAttributeModifiableErrorMessage(final String expectedErrorMessage) {
        // String expectedErrorMessage, String noElementMessage, String assertMessage
        assertErrorMessageAppears(expectedErrorMessage, "Expected error message, but none was present", "Error message not as expected");
    }

    /**
     * Asserts the appearance of error messages with expected messages for notification empty fields.
     */
    public void assertNotificationNotFilledErrorMessages() {
        String[] expectedErrorMessages = {"You must fill in a notification sender if notification is to be used.",
                "You must fill in a notification subject if notification is to be used.",
                "You must fill in a notification message if notification is to be used."};
        assertAllErrorMessagesAppear(expectedErrorMessages,
                "Notification not filled error message element not found!",
                "Unexpected save enpty notification message!");
    }

    /**
     * Sets the value for the attribute specified by its type and index in the section 'Subject DN Attributes'.
     *
     * @param attributeType  attribute's type.
     * @param attributeIndex attribute's index.
     * @param value          attribute's value.
     */
    public void fillSubjectAttributesAttributeValue(final String attributeType, final int attributeIndex, final String value) {
        fillInput(Page.getSubjectAttributesAttributeTextfieldByAttributeTypeAndAttributeIndex(attributeType, attributeIndex), value);
    }

    public void triggerBatchGeneration() {
        clickLink(Page.INPUT_BATCH_GENERATION);
    }

    public void triggerCustomCertificateSerialNumber() {
        clickLink(Page.INPUT_CUSTOM_SERIAL_NUMBER);
    }

    // Asserts the title text
    private void assertEndEntityProfileTitleExists(final String endEntityProfileName) {
        final WebElement endEntityProfileTitle = findElement(Page.TEXT_TITLE_END_ENTITY_PROFILE);
        if (endEntityProfileTitle == null) {
            fail("End Entity Profile title was not found.");
        }
        assertEquals(
                "Unexpected title on End Entity Profile 'Edit' page",
                "End Entity Profile: " + endEntityProfileName,
                endEntityProfileTitle.getText()
        );
    }

    /**
     * Clicks the Cancel button when editing an End Entity Profile.
     */
    public void cancel() {
        webDriver.findElement(Page.BUTTON_CANCEL_EDITING_PROFILE).click();
    }

    /**
     * Asserts no notification exists on page
     */
    public void assertNotificationDoesNotExist() {
        assertElementDoesNotExist(Page.NOTIFICATION, "There were notifications displayed upon creation of EEP");
    }

    /**
     * Returns the text value of notification sender
     *
     * @param inputIndex the index of notification to check
     * @return the text value of notification sender or null
     */
    public String getNotificationSenderText(final int inputIndex) {
        return getElementText(Page.getNotificationSenderByIndex(inputIndex));
    }

    /**
     * Asserts existence of 'Notification sender' input for notification with provided index
     *
     * @param senderIndex the index of notification to check
     */
    public void assertNotificationSenderExists(int senderIndex) {
        assertElementExists(Page.getNotificationSenderByIndex(senderIndex), "Notification sender with index " + senderIndex + " is displayed on edit EEP page");
    }

    /**
     * Asserts 'Notification sender' input for notification with provided index does not exist on page
     *
     * @param senderIndex the index of notification to check
     */
    public void assertNotificationSenderDoesNotExist(int senderIndex) {
        assertElementDoesNotExist(
                Page.getNotificationSenderByIndex(senderIndex),
                "Notification sender with index " + senderIndex + " is displayed on edit EEP page"
        );
    }

    /**
     * @param inputIndex the index of notification to check
     */
    public String getNotificationSubjectValueText(final int inputIndex) {
        return getElementValue(Page.getNotificationSubjectByIndex(inputIndex));
    }

    /**
     * Returns the text value of notification sender for notification with provided index
     *
     * @param inputIndex the index of notification to check
     * @return the text value of notification sender or null
     */
    public String getNotificationSenderValueText(final int inputIndex) {
        return getElementValue(Page.getNotificationSenderByIndex(inputIndex));
    }

    /**
     * Returns the value (attribute 'value') of delete notification button with provided index
     *
     * @param buttonIndex the index of notification to check
     * @return button's value or null.
     */
    public String getNotificationDeleteButtonValueText(final int buttonIndex) {
        return getElementValue(Page.getDeleteNotificationButtonByIndex(buttonIndex));
    }

    /**
     * Asserts existence of 'Notification subject' input
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationSubjectExists(final int inputIndex) {
        assertElementExists(Page.getNotificationSubjectByIndex(inputIndex), "Notification subject is not present on edit EEP page after adding notification");
    }

    /**
     * Asserts an existence of 'Notification message' textarea.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationMessageExists(final int inputIndex) {
        assertElementExists(Page.getNotificationMessageByIndex(inputIndex), "Notification message is not present on edit EEP page after adding notification");
    }

    /**
     * Asserts an existence of 'Notification Recipient' input.
     * @param inputIndex the index of notification to check
     */
    public void assertNotificationRecipientExists(final int inputIndex) {
        assertElementExists(Page.getNotificationRecipientByIndex(inputIndex), "Notification recipient is not present on edit EEP page after adding notification");
    }

    /**
     * Asserts an existence of 'Notification Events' select.
     */
    public void assertNotificationEventsExists() {
        assertElementExists(Page.getNotificationEventsByIndex(0), "Notification events is not present on edit EEP page after adding notification");
    }

    /**
     * Verify notification fields are enabled/disabled for all present notifications
     *
     * @param isEnabled true for enabled and false for disabled
     * @param maxFieldIndex the maximun index for existing notifications. Count starts from 0;
     */
    public void verifyNotificationFieldsEnabled(boolean isEnabled, int maxFieldIndex) {
        assertDefaultSendNotificationIsEnabled(isEnabled);
        assertRequiredSendNotificationIsEnabled(isEnabled);
        assertDeleteAllNotificationButtonIsEnabled(isEnabled);
        assertAddNotificationButtonIsEnabled(isEnabled);
        for (int i = 0; i <= maxFieldIndex; i++) {
            assertDeleteNotificationButtonIsEnabled(isEnabled, i);
            assertNotificationSenderInputIsEnabled(isEnabled, i);
            assertNotificationSubjectInputIsEnabled(isEnabled, i);
            assertNotificationRecipientInputIsEnabled(isEnabled, i);
            assertNotificationEventsInputIsEnabled(isEnabled, i);
            assertNotificationTextareaInputIsEnabled(isEnabled, i);
        }
    }
    
    /**
     * Trigger the 'End Entity Email' use checkbox.
     *
     */
    public void triggerEndEntityEmailCheckBox() {
        clickLink(Page.INPUT_USE_END_ENTITY_EMAIL);
    }

    /**
     * Trigger the checkbox for 'Subject DN Attribute' - Required.
     *
     * @param dnAttributeName Name of the 'Subject DN Attribute'.
     */
    public void subjectDnAttributeRequiredCheckboxTrigger(final String dnAttributeName) {
        clickLink(Page.getSubjectDnAttributesCheckBox(dnAttributeName, "Required"));
    }

    private void assertSubjectDnAttributesCheckboxIsChecked(final String dnAttributeName, final String checkboxName, final boolean expectedState) {
        assertEquals("'" + checkboxName + "' checkbox for '" + dnAttributeName + "' should be " + expectedState + ".",
                expectedState,
                isSelectedElement(Page.getSubjectDnAttributesCheckBox(dnAttributeName, checkboxName))
        );
    }

    /**
     * Checks the state of checkbox for 'Subject DN Attribute' - Required.
     *
     * @param expectedState boolean representing the state.
     */
    public void assertSubjectDnAttributesRequiredCheckboxIsChecked(final String dnAttributeName, final boolean expectedState) {
        assertSubjectDnAttributesCheckboxIsChecked(dnAttributeName, "Required", expectedState);
    }

    /**
     * Checks the state of checkbox for 'Subject DN Attribute' - Modifiable.
     *
     * @param expectedState boolean representing the state.
     */
    public void assertSubjectDnAttributesModifiableCheckboxIsChecked(final String dnAttributeName, final boolean expectedState) {
        assertSubjectDnAttributesCheckboxIsChecked(dnAttributeName, "Modifiable", expectedState);
    }

    /**
     * Checks the state of checkbox for 'Subject DN Attribute' - Validation.
     *
     * @param expectedState boolean representing the state.
     */
    public void assertSubjectDnAttributesValidationCheckboxIsChecked(final String dnAttributeName, final boolean expectedState) {
        assertSubjectDnAttributesCheckboxIsChecked(dnAttributeName, "Validation", expectedState);
    }

    /**
     * Asserts the Default Certificate Profile has selected name.
     *
     * @param name selected name.
     */
    public void assertDefaultCertificateProfileNameSelected(final String name) {
        assertTrue("Default Certificate Profile value mismatch.", getSelectSelectedNames(Page.SELECT_DEFAULT_CP).contains(name));
    }

    /**
     * Asserts the Available Certificate Profiles has selected names.
     *
     * @param names selected names.
     */
    public void assertAvailableCertificateProfilesNamesSelected(final String... names) {
        for(String name : names) {
            assertTrue("Available Certificate Profiles value mismatch [" + name + "].", getSelectSelectedNames(Page.SELECT_AVAILABLE_CERTIFICATE_PROFILES).contains(name));
        }
    }

    /**
     * Asserts the Default CA has selected name.
     *
     * @param name selected name.
     */
    public void assertDefaultCaNameSelected(final String name) {
        assertTrue("Default CA value mismatch.", getSelectSelectedNames(Page.SELECT_DEFAULT_CA).contains(name));
    }

    /**
     * Asserts the Default Token has selected name.
     *
     * @param name selected name.
     */
    public void assertDefaultTokenNameSelected(final String name) {
        assertTrue("Default CA value mismatch.", getSelectSelectedNames(Page.SELECT_DEFAULT_TOKEN).contains(name));
    }

    /**
     * Asserts the Available Tokens has selected names.
     *
     * @param names selected names.
     */
    public void assertAvailableTokensNamesSelected(final String... names) {
        for(String name : names) {
            assertTrue("Available Tokens value mismatch [" + name + "].", getSelectSelectedNames(Page.SELECT_AVAILABLE_TOKENS).contains(name));
        }
    }
}