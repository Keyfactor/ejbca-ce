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

import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Validator helper class for EJBCA Web Tests.
 * @version $Id$
 *
 */
public class ValidatorsHelper extends BaseHelper {

    public ValidatorsHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    /**
     * Contains constants and references of the 'Validators' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editvalidators/editvalidators.xhtml";
        static final By PAGE_LINK = By.id("caEditvalidators");
        
        // Input fields
        static final By INPUT_NAME = By.id("editvalidators:listValidatorsDataTable:validatorNameInputField");
        static final By INPUT_CLONE_NEW_NAME = By.id("editvalidators:addFromTemplateValidatorNew");
        static final By INPUT_RENAME_NEW_NAME = By.id("editvalidators:renameValidatorNew");
        static final By INPUT_DESCRIPTION = By.id("kvf:description");
        static final By INPUT_BROWSE_BLACKLIST_FILE = By.id("kvf:blacklist_upload");
        // Buttons
        static final By BUTTON_ADD = By.xpath("//input[@value='Add']");
        static final By BUTTON_RENAME_CONFIRM = By.xpath("//input[@value='Confirm new name']");
        static final By BUTTON_RENAME_CANCEL = By.xpath("//input[@value='Cancel']");
        static final By BUTTON_CLONE_CONFIRM = By.xpath("//input[@value='Create from template']");
        static final By BUTTON_CLONE_CANCEL = By.xpath("//input[@value='Cancel']");
        static final By BUTTON_DELETE_CONFIRM = By.xpath("//input[@value='Confirm deletion']");
        static final By BUTTON_DELETE_CANCEL = By.xpath("//input[@value='Cancel']");
        static final By BUTTON_SAVE_EDIT = By.xpath("//input[@value='Save']");
        static final By BUTTON_CANCEL_EDIT = By.xpath("//input[@value='Cancel']");

        // Check boxes
        static final By CHECKBOX_APPLY_FOR_ALL_PROFILES = By.id("kvf:allcertificateprofiles");
        
        // Texts
        static final By TEXT_TITLE_EDIT_VALIDATOR = By.id("titleValidator");
        static final By TEXT_TITLE_DELETE_VALIDATOR = By.id("editvalidators:deleteValidatorName");
        static final By TEXT_TITLE_CLONE_VALIDATOR = By.id("editvalidators:addFromTemplateValidatorOld");
        static final By TEXT_TITLE_RENAME_VALIDATOR = By.id("editvalidators:renameValidatorOld");
        
        // Select
        static final By SELECT_VALIDATOR_TYPE = By.id("kvf:validatorType");
        static final By SELECT_ISSUANCE_PHASE = By.id("kvf:applicablePhase");
        static final By SELECT_APPLY_FOR_PROFILES = By.id("kvf:selectapplicablecertificateprofiles");
        static final By SELECT_VALIDATION_FAIL_ACTION = By.id("kvf:selectfailedaction");
        static final By SELECT_VALIDATOR_NOT_APPLICABLE_ACTION = By.id("kvf:selectnotapplicableaction");
        
        // Dynamic references
        static final String TABLE_VALIDATORS = "//*[@id='editvalidators:listValidatorsDataTable']";
        
        static By getEditButtonFromValidatorsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Edit']");
        }
        static By getViewButtonFromValidatorsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='View']");
        }
        static By getDeleteButtonFromValidatorsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Delete']");
        }
        static By getRenameButtonFromValidatorsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Rename']");
        }
        static By getCloneButtonFromValidatorsTableRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]/following-sibling::td//input[@value='Clone']");
        }
        static By getValidatorRowContainingText(final String text) {
            return By.xpath("//tr/td[contains(text(), '" + text + "')]");
        }
    }
    
    
    /**
     * Opens the page 'Validators' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    /**
     * Opens the edit page for a Validator, then asserts that the correct Validator is being edited.
     *
     * @param validatorName a Validator name.
     */
    public void openEditValidatorPage(final String validatorName) {
        // Click edit button for Validator
        clickLink(Page.getEditButtonFromValidatorsTableRowContainingText(validatorName));
        // Assert correct edit page
        assertValidatorTitleExists(Page.TEXT_TITLE_EDIT_VALIDATOR, "Validator: ", validatorName);
    }
    
    /**
     * Opens the view page for a Validator, then asserts that the correct Validator is being viewed.
     *
     * @param validatorName a Validator name.
     */
    public void openViewValidatorPage(final String validatorName) {
        // Click edit button for Validator
        clickLink(Page.getViewButtonFromValidatorsTableRowContainingText(validatorName));
        // Assert correct edit page
        assertValidatorTitleExists(Page.TEXT_TITLE_EDIT_VALIDATOR, "Validator: ", validatorName);
    }
    
    /**
     * Adds a new Validator, and asserts that it appears in Validators table.
     *
     * @param validatorName a Validator name.
     */
    public void addValidator(final String validatorName) {
        fillInput(Page.INPUT_NAME, validatorName);
        clickLink(Page.BUTTON_ADD);
        // Assert Validator exists
        assertValidatorNameExists(validatorName);
    }
    
    /**
     * Opens the 'Validator' deletion dialog.
     *
     * @param validatorName a name of profile for deletion.
     */
    public void deleteValidator(final String validatorName) {
        // Click 'Delete' button
        clickLink(Page.getDeleteButtonFromValidatorsTableRowContainingText(validatorName));
        // Assert that the correct Validator is being deleted
        assertValidatorTitleExists(Page.TEXT_TITLE_DELETE_VALIDATOR, validatorName);
    }
    
    /**
     * Renames the Validator and asserts the appearance of renamed profile.
     *
     * @param oldValidatorName current name.
     * @param newValidatorName new name.
     */
    public void renameValidator(final String oldValidatorName, final String newValidatorName) {
        // Click 'Rename' button
        clickLink(Page.getRenameButtonFromValidatorsTableRowContainingText(oldValidatorName));
        // Assert that the correct Validator is being renamed
        assertValidatorTitleExists(Page.TEXT_TITLE_RENAME_VALIDATOR, oldValidatorName);
        // Enter new name for Validator
        fillInput(Page.INPUT_RENAME_NEW_NAME, newValidatorName);
        // Rename Validator
        clickLink(Page.BUTTON_RENAME_CONFIRM);
        // Assert Validator exists
        assertValidatorNameExists(newValidatorName);
    }
    
    /**
     * Clones the 'Validator' and asserts that both of them old a new exist.
     *
     * @param validatorName source Validator name.
     * @param newValidatorName name of the cloned Validator.
     */
    public void cloneValidatorProfile(final String validatorName, final String newValidatorName) {
        // Click 'Clone' button
        clickLink(Page.getCloneButtonFromValidatorsTableRowContainingText(validatorName));
        // Assert that the correct Validator is being cloned
        assertValidatorTitleExists(Page.TEXT_TITLE_CLONE_VALIDATOR, validatorName);
        // Enter name for new Validator
        fillInput(Page.INPUT_CLONE_NEW_NAME, newValidatorName);
        // Clone Validator
        clickLink(Page.BUTTON_CLONE_CONFIRM);
        // Assert Validator exist
        assertValidatorNameExists(validatorName);
        assertValidatorNameExists(newValidatorName);
    }
    
    /**
     * Changes the Validator type to validatorType by selecting from the drop-down list of Validators.
     * @param validatorType
     */
    public void setValidatorType(final String validatorType) {
        selectOptionByName(Page.SELECT_VALIDATOR_TYPE, validatorType);
    }

    /**
     * Select a blacklist validator filename.
     *
     * @param filename
     */

    public void setBlacklistFile(final String filename) {
        fillInput(Page.INPUT_BROWSE_BLACKLIST_FILE, filename);
    }

    /**
     * Sets the description for the currently validator being edited.
     * @param description free text
     */
    public void setDescription(final String description) {
        fillTextarea(Page.INPUT_DESCRIPTION, description, true);
    }

    /**
     * Changes the 'Issuance Phase' by selecting from the drop-down in 'General Settings'.
     * @param phase to select
     */
    public void setIssancePhase(final String phase) {
        selectOptionByName(Page.SELECT_ISSUANCE_PHASE, phase);
    }
    
    /**
     * Selects a single profile from the list of available certificate profiles.
     * @param profileName of the certificate profile
     */
    public void setApplyForCertificateProfile(final String profileName) {
        selectOptionByName(Page.SELECT_APPLY_FOR_PROFILES, profileName);
    }
    
    /**
     * Selects multiple profiles from the list of available certificate profiles.
     * @param profileNames list of trings containing all profiles to select
     */
    public void setApplyForCertificateProfile(final List<String> profileNames) {
        selectOptionsByName(Page.SELECT_APPLY_FOR_PROFILES, profileNames);
    }
    
    /**
     * Changes the 'If Validation failed' by selecting from the drop-down in 'General Settings'.
     * @param action
     */
    public void setValidationFailedAction(final String action) {
        selectOptionByName(Page.SELECT_VALIDATION_FAIL_ACTION, action);
    }

    /**
     * Changes the 'If Validator was not applicable' by selecting from the drop-down in 'General Settings'.
     * @param action
     */
    public void setValidatorNotApplicableAction(final String action) {
        selectOptionByName(Page.SELECT_VALIDATOR_NOT_APPLICABLE_ACTION, action);
    }
    
    /**
     * Triggers the input 'Apply for Certificate Profiles'.
     */
    public void triggerApplyForAllCertificateProfiles() {
        clickLink(Page.CHECKBOX_APPLY_FOR_ALL_PROFILES);
    }
    
    /**
     * Saves the 'Validator' and asserts the success.
     */
    public void saveValidator() {
        clickLink(Page.BUTTON_SAVE_EDIT);
        assertValidatorSaved();
    }
    
    /**
     * Cancels the edit of the 'Validator' by clicking cancel button.
     */
    public void cancelEditValidator() {
        clickLink(Page.BUTTON_CANCEL_EDIT);
    }
    
    // Asserts the 'Validator saved.' save title exists.
    private void assertValidatorSaved() {
        assertInfoMessageAppears("Validator saved.",
                "Validator save message was not found.",
                "Expected Validator save message was not displayed");
    }
    
    /**
     * Asserts the Validator name exists in the list.
     *
     * @param validatorName name of the Validator.
     */
    public void assertValidatorNameExists(final String validatorName) {
        assertElementExists(
                Page.getValidatorRowContainingText(validatorName),
                validatorName + " was not found on 'Validators' page."
        );
    }
    
    // Asserts the 'Validator' name title exists.
    private void assertValidatorTitleExists(final By textTitleId, final String validatorName) {
        assertValidatorTitleExists(textTitleId, "", validatorName);
    }
    
    // Asserts the 'Validator' name title exists.
    private void assertValidatorTitleExists(final By textTitleId, final String prefixString, final String validatorName) {
        final WebElement validatorTitle = findElement(textTitleId);
        if(validatorName == null) {
            fail("Validator title was not found.");
        }
        assertEquals(
                "Action on wrong Validator.",
                prefixString + validatorName,
                validatorTitle.getText()
        );
    }
}






