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

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO JavaDoc
/**
 * Helper class for handling 'Approval Profiles' page in automated web tests.
 *
 * @version $Id$
 */
public class ApprovalProfilesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Approval Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/approval/editapprovalprofiles.xhtml";
        static final By PAGE_LINK = By.id("supervisionEditapprovalprofiles");
        // Profiles list
        static final By INPUT_APPROVAL_PROFILE_NAME = By.id("editapprovalprofilesForm:approvalTable:approvalProfileName");
        static final By BUTTON_ADD = By.id("editapprovalprofilesForm:approvalTable:addButton");
        // Form
        static final By SELECT_APPROVAL_PROFILE_TYPE = By.id("approvalProfilesForm:selectOneMenuApprovalType");
        static final By INPUT_REQUEST_EXPIRATION_PERIOD = By.id("approvalProfilesForm:reqExpPeriod");
        static final By INPUT_APPROVAL_EXPIRATION_PERIOD = By.id("approvalProfilesForm:approvalExpPeriod");
        static final By INPUT_MAX_EXTENSION_TIME = By.id("approvalProfilesForm:maxExtensionTime");
        static final By INPUT_ALLOW_SELF_APPROVED_REQUEST_EDITING = By.id("approvalProfilesForm:selfApproveEdit");
        static final By BUTTON_ADD_STEP = By.id("approvalProfilesForm:addStepButton");
        static final By BUTTON_SAVE = By.id("approvalProfilesForm:saveButton");
        static final By BUTTON_CANCEL = By.id("approvalProfilesForm:cancelButton");
        static final By BUTTON_BACK = By.id("approvalProfilesForm:backButton");
        static final By BUTTON_ADD_PARTITION = By.xpath(".//input[@value='Add Partition']");
        static final By BUTTON_DELETE_STEP = By.xpath(".//input[@value='Delete Step']");
        static final By TEXT_TITLE_EDIT_APPROVAL_PROFILE = By.id("titleApprovalProfile");
        static final By TABLE_APPROVAL_STEPS = By.id("approvalProfilesForm:approvalStepsTable");
        // Relative locators
        static final By TABLE_APPROVAL_STEPS_ROWS = By.xpath("./tbody/tr/td");
        static final By TABLE_APPROVAL_STEP_PARTITIONS = By.xpath(".//table[@class='subTable']");
        static final By BUTTON_APPROVAL_STEP_PARTITION_DELETE_PARTITION = By.xpath(".//input[@value='Delete Partition']");
        static final By BUTTON_APPROVAL_STEP_PARTITION_ADD_NOTIFICATION = By.xpath(".//input[@value='Add notification']");
        static final By BUTTON_APPROVAL_STEP_PARTITION_ADD_USER_NOTIFICATION = By.xpath(".//input[@value='Add user notification']");
        static final By INPUT_APPROVAL_STEP_PARTITION_NAME = By.xpath(".//input[contains(@id,'approvalProfilesForm:approvalStepsTable:') and contains(@id,':inputString') and @type='text']");
        static final By SELECT_APPROVAL_STEP_PARTITION_ROLES_SELECT = By.xpath(".//td[@class='editColumn2-Approval-steps']/select[contains(@name,'approvalProfilesForm:approvalStepsTable:')]");
        static final By SELECT_APPROVAL_STEP_PARTITION_FIELD_LABEL = By.xpath(".//input[contains(@id,'approvalProfilesForm:approvalStepsTable:') and contains(@id, ':fieldLabel')]");
        static final By SELECT_APPROVAL_STEP_PARTITION_FIELD_TYPE_SELECT = By.xpath(".//select[contains(@id,'approvalProfilesForm:approvalStepsTable:') and contains(@id,':selectAction')]");
        static final By BUTTON_APPROVAL_STEP_PARTITION_ADD_FIELD = By.xpath(".//input[contains(@id,'approvalProfilesForm:approvalStepsTable:') and contains(@id,':fieldAdd')]");

        static class APPROVAL_STEP_PARTITION_FIELD_TYPE {
            static final String CHECK_BOX = "Check Box";
            static final String NUMBER_SHORT = "Number (Short)";
            static final String NUMBER_LONG = "Number (Long)";
            static final String RADIO_BUTTON = "Radio Button";
            static final String TEXT_FIELD = "Text Field";
            //
            static final List<String> ALL_TYPES = Arrays.asList(CHECK_BOX, NUMBER_SHORT, NUMBER_LONG, RADIO_BUTTON, TEXT_FIELD);
            //
            static final By INPUT_CHECKBOX = By.xpath(".//input[@type='checkbox']");
            static final By INPUT_RADIO = By.xpath(".//input[@type='radio']");
            static final By INPUT_RADIO_LABEL = By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='text']");
            static final By INPUT_RADIO_LABEL_ADD = By.xpath("//span[contains(text(), 'Radio Button Label:')]/input[@type='submit']");
            static final By INPUT_INTEGER = By.xpath(".//input[@value='0']");
        }

        // Dynamic references' parts
        static final String TABLE_APPROVAL_PROFILES = "//*[@id='editapprovalprofilesForm:approvalTable']";

        // Dynamic references
        static By getAPTableRowContainingText(final String text) {
            return By.xpath("//tbody/tr/td[contains(text(), '" + text + "')]");
        }

        static By getViewButtonFromAPTableRowContainingText(final String text) {
            return By.xpath(TABLE_APPROVAL_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='View']");
        }

        static By getEditButtonFromAPTableRowContainingText(final String text) {
            return By.xpath(TABLE_APPROVAL_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Edit']");
        }
    }

    public ApprovalProfilesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Approval Profiles' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    public void addApprovalProfile(final String approvalProfileName){
        fillInput(Page.INPUT_APPROVAL_PROFILE_NAME, approvalProfileName);
        clickLink(Page.BUTTON_ADD);
        assertApprovalProfileNameExists(approvalProfileName);
    }

    /**
     * Opens the edit page for a Approval Profile, then asserts that the correct Approval Profile is being edited.
     *
     * @param approvalProfileName an Approval Profile name.
     */
    public void openEditApprovalProfilePage(final String approvalProfileName) {
        // Click edit button for Approval Profile
        clickLink(Page.getEditButtonFromAPTableRowContainingText(approvalProfileName));
        // Assert correct edit page
        assertApprovalProfileTitleExists(Page.TEXT_TITLE_EDIT_APPROVAL_PROFILE, "Approval Profile: ", approvalProfileName);
    }

    /**
     * Opens the view page for a Approval Profile, then asserts that the correct Approval Profile is being viewed.
     *
     * @param approvalProfileName an Approval Profile name.
     */
    public void openViewApprovalProfilePage(final String approvalProfileName) {
        // Click edit button for Approval Profile
        clickLink(Page.getViewButtonFromAPTableRowContainingText(approvalProfileName));
        // Assert correct edit page
        assertApprovalProfileTitleExists(Page.TEXT_TITLE_EDIT_APPROVAL_PROFILE, "Approval Profile: ", approvalProfileName);
    }

    public void assertApprovalSteps(final int expectedNumberOfSteps, final List<String> roleNames) {
        final List<WebElement> approvalSteps = getApprovalStepsRows();
        assertEquals("Unexpected number of steps", expectedNumberOfSteps, approvalSteps.size());
        // Check Steps
        for(WebElement approvalStep : approvalSteps) {
            // Check for button
            assertApprovalStepHasDeleteStepButton(approvalStep);
            final List<WebElement> approvalStepPartitions = getApprovalStepPartitions(approvalStep);
            for(WebElement approvalStepPartition : approvalStepPartitions) {
                assertApprovalStepsPartitionHasPartitionManagementButtons(approvalStep, approvalStepPartition);
                assertApprovalStepsPartitionHasForm(approvalStepPartition, roleNames, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.ALL_TYPES);
            }
        }
    }

    public void assertApprovalStepHasDeleteStepButton(final WebElement approvalStep) {
        final WebElement buttonDeleteStep = findElement(approvalStep, Page.BUTTON_DELETE_STEP);
        assertNotNull("Approval step doesn't have 'Delete Step' button.", buttonDeleteStep);
    }

    public void assertApprovalStepsPartitionHasPartitionManagementButtons(final WebElement approvalStep, final WebElement approvalStepPartition) {
        final WebElement buttonDeletePartition = approvalStepPartition.findElement(Page.BUTTON_APPROVAL_STEP_PARTITION_DELETE_PARTITION);
        assertNotNull("Approval step's partition doesn't have 'Delete Partition' button.", buttonDeletePartition);
        final WebElement buttonAddNotification = approvalStepPartition.findElement(Page.BUTTON_APPROVAL_STEP_PARTITION_ADD_NOTIFICATION);
        assertNotNull("Approval step's partition doesn't have 'Add notification' button.", buttonAddNotification);
        final WebElement buttonAddUserNotification = approvalStepPartition.findElement(Page.BUTTON_APPROVAL_STEP_PARTITION_ADD_USER_NOTIFICATION);
        assertNotNull("Approval step's partition doesn't have 'Add user notification' button.", buttonAddUserNotification);
        //
        final WebElement buttonAddPartition = findElement(approvalStep, Page.BUTTON_ADD_PARTITION);
        assertNotNull("Approval step doesn't have 'Add Partition' button.", buttonAddPartition);
    }

    public void assertApprovalStepsPartitionHasForm(final WebElement approvalStepPartition, final List<String> selectRoles, final List<String> partitionFieldTypes) {
        // Name
        final WebElement inputPartitionName = findElement(approvalStepPartition, Page.INPUT_APPROVAL_STEP_PARTITION_NAME);
        assertNotNull("Approval step's partition doesn't have 'Name' input.", inputPartitionName);
        // Get selectors 'Roles which may approve this partition' and 'Roles which may view this partition'
        final List<WebElement> selectPartitionRoles = findElements(approvalStepPartition, Page.SELECT_APPROVAL_STEP_PARTITION_ROLES_SELECT);
        assertEquals(
                "Approval step's partition doesn't have 'Roles which may approve this partition' and 'Roles which may view this partition' selectors.",
                2,
                selectPartitionRoles.size());
        // Roles which may approve this partition:
        final List<String> selectApproveRoles = getSelectNames(selectPartitionRoles.get(0));
        for(String role : selectRoles) {
            assertTrue("Approval partition's selector 'Roles which may approve this partition' doesn't have '" + role + "' role.", selectApproveRoles.contains(role));
        }
        // Roles which may view this partition:
        final List<String> selectViewRoles = getSelectNames(selectPartitionRoles.get(1));
        for(String role : selectRoles) {
            assertTrue("Approval partition's selector 'Roles which may view this partition' doesn't have '" + role + "' role.", selectViewRoles.contains(role));
        }
        // Select field type
        final WebElement selectFieldType = findElement(approvalStepPartition, Page.SELECT_APPROVAL_STEP_PARTITION_FIELD_TYPE_SELECT);
        assertNotNull("Approval step's partition doesn't have field type select.", selectFieldType);
        final List<String> selectApprovalTypeNames = getSelectNames(selectFieldType);
        for(String partitionApprovalType : partitionFieldTypes) {
            assertTrue("Approval partition's type selector doesn't have '" + partitionApprovalType + "' role.", selectApprovalTypeNames.contains(partitionApprovalType));
        }
        // Label
        final WebElement inputFieldLabel = findElement(approvalStepPartition, Page.SELECT_APPROVAL_STEP_PARTITION_FIELD_LABEL);
        assertNotNull("Approval step doesn't have 'Label:' input.", inputFieldLabel);
        // Add button
        final WebElement buttonAddField = findElement(approvalStepPartition, Page.BUTTON_APPROVAL_STEP_PARTITION_ADD_FIELD);
        assertNotNull("Approval step doesn't have 'Add Partition' button.", buttonAddField);
    }

    public void assertAddStepButtonPresent() {
        assertElementExists(Page.BUTTON_ADD_STEP, "Add Step button does not exist");
    }

    public void assertBackButtonPresent() {
        assertElementExists(Page.BUTTON_BACK, "Back button does not exist");
    }

    public void assertFormsSaveAndCancelButtonsPresent() {
        assertElementExists(Page.BUTTON_SAVE, "Save button does not exist");
        assertElementExists(Page.BUTTON_CANCEL, "Cancel button does not exist");
    }

    /**
     * Sets Approval Profile Type by value.
     *
     * @param value Approval Profile type value to be selected.
     */
    public void setApprovalProfileType(final String value) {
        selectOptionByName(Page.SELECT_APPROVAL_PROFILE_TYPE, value);
    }

    /**
     * Sets the 'Request Expiration Period' of approval profile.
     *
     * @param value request expiration period's (*y *mo *d *h *m) value.
     */
    public void setRequestExpirationPeriod(final String value) {
        fillInput(Page.INPUT_REQUEST_EXPIRATION_PERIOD, value);
    }

    /**
     * Sets the 'Approval Expiration Period' of approval profile.
     *
     * @param value approval expiration period (*y *mo *d *h *m) value.
     */
    public void setApprovalExpirationPeriod(final String value) {
        fillInput(Page.INPUT_APPROVAL_EXPIRATION_PERIOD, value);
    }

    /**
     * Saves the approval profile.
     */
    public void saveApprovalProfile() {
        clickLink(Page.BUTTON_SAVE);
    }

    public void addStep(final int expectedNumberOfSteps, final List<String> roleNames) {
        // Add a new step
        clickLink(Page.BUTTON_ADD_STEP);
        assertApprovalSteps(expectedNumberOfSteps, roleNames);
    }

    public void addPartition(final int approvalStepIndex, final int expectedNumberOfSteps, final List<String> roleNames) {
        // Add partition
        addPartitionToApprovalStep(approvalStepIndex);
        // Reload ApprovalSteps
        final List<WebElement> approvalSteps = getApprovalStepsRows();
        final WebElement approvalStep = getApprovalStepByIndex(approvalSteps, approvalStepIndex);
        final List<WebElement> approvalStepsPartitions = getApprovalStepPartitions(approvalStep);
        assertEquals("Unexpected number of partitions in step 1 after adding an extra partition", 2, approvalStepsPartitions.size());
        // Verify content of both partitions again
        assertApprovalSteps(expectedNumberOfSteps, roleNames);
    }

    public void addField(final int approvalStepIndex, final int approvalStepPartitionIndex, final String fieldTypeName) {
        final WebElement approvalStepPartition = getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex);
        final WebElement selectFieldType = findElement(approvalStepPartition, Page.SELECT_APPROVAL_STEP_PARTITION_FIELD_TYPE_SELECT);
        selectOptionByName(selectFieldType, fieldTypeName);
        clickLink(findElement(approvalStepPartition, Page.BUTTON_APPROVAL_STEP_PARTITION_ADD_FIELD));
    }

    public void addFieldRadioButtonLabel(final int approvalStepIndex, final int approvalStepPartitionIndex, final String labelName) {
        final WebElement approvalStepPartition = getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex);
        final WebElement radioButtonHolder = findElement(approvalStepPartition, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.INPUT_RADIO_LABEL);
        fillInput(radioButtonHolder, labelName);
        final WebElement addRowButton = findElement(approvalStepPartition, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.INPUT_RADIO_LABEL_ADD);
        clickLink(addRowButton);
    }

    public void assertApprovalStepPartitionFieldTypeExists(final int approvalStepIndex, final int approvalStepPartitionIndex, final String fieldTypeName, final int expectedNumberOfElements) {
        final WebElement approvalStepPartition = getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex);
        if(Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.CHECK_BOX.equals(fieldTypeName)) {
            findElement(approvalStepPartition, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.INPUT_CHECKBOX);
            return;
        }
        if(Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.RADIO_BUTTON.equals(fieldTypeName)) {
            final List<WebElement> radioButtons = findElements(approvalStepPartition, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.INPUT_RADIO);
            assertEquals("Cannot find the expected number of radio button elements.", expectedNumberOfElements, radioButtons.size());
            return;
        }
        if(Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.NUMBER_SHORT.equals(fieldTypeName)) {
            findElement(approvalStepPartition, Page.APPROVAL_STEP_PARTITION_FIELD_TYPE.INPUT_INTEGER);
            return;
        }
        fail("Please check your test scenario action, this assertion cannot be applied.");
    }

    public void setApprovalStepPartitionName(final int approvalStepIndex, final int approvalStepPartitionIndex, final String name) {
        final WebElement approvalStepPartition = getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex);
        final WebElement nameInput = findElement(approvalStepPartition, Page.INPUT_APPROVAL_STEP_PARTITION_NAME);
        fillInput(nameInput, name);
    }

    public void setApprovalStepPartitionApprovePartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final String roleName) {
        setApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, 0, roleName);
    }

    public void setApprovalStepPartitionViewPartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final String roleName) {
        setApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, 1, roleName);
    }

    public void assertApprovalProfileTypeSelectedName(final String selectName) {
        assertEquals(
                "'Approval Profile Type' has unexpected selection",
                selectName,
                getFirstSelectedOption(Page.SELECT_APPROVAL_PROFILE_TYPE)
        );
    }

    public void assertRequestExpirationPeriodHasValue(final String value) {
        assertEquals(
                "'Request Expiration Period' has unexpected value",
                value,
                getElementValue(Page.INPUT_REQUEST_EXPIRATION_PERIOD)
        );
    }

    public void assertApprovalExpirationPeriodHasValue(final String value) {
        assertEquals(
                "'Approval Expiration Period' has unexpected value",
                value,
                getElementValue(Page.INPUT_APPROVAL_EXPIRATION_PERIOD)
        );
    }

    public void assertApprovalStepPartitionNameHasValue(final int approvalStepIndex, final int approvalStepPartitionIndex, final String expectedNameValue) {
        assertEquals(
                "'Name' has unexpected value",
                expectedNameValue,
                getElementValue(
                        findElement(
                                getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex),
                                Page.INPUT_APPROVAL_STEP_PARTITION_NAME)
                )
        );
    }

    public void assertApprovalStepPartitionApprovePartitionRolesHasSelectionSize(final int approvalStepIndex, final int approvalStepPartitionIndex, final int expectedSize) {
        assertEquals(
                "'Roles which may approve this partition' has unexpected number of selected options",
                expectedSize,
                getApprovalStepPartitionRoleSelectionSize(approvalStepIndex, approvalStepPartitionIndex, 0)
        );
    }

    public void assertApprovalStepPartitionHasApprovePartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final String expectedRoleName) {
        assertEquals(
                "'Roles which may approve this partition' has unexpected selections",
                expectedRoleName,
                getApprovalStepPartitionRoleSelection(approvalStepIndex, approvalStepPartitionIndex, 0)
        );
    }

    public void assertApprovalStepPartitionViewPartitionRolesHasSelectionSize(final int approvalStepIndex, final int approvalStepPartitionIndex, final int expectedSize) {
        assertEquals(
                "'Roles which may view this partition' has unexpected number of selected options",
                expectedSize,
                getApprovalStepPartitionRoleSelectionSize(approvalStepIndex, approvalStepPartitionIndex, 1)
        );
    }

    public void assertApprovalStepPartitionHasViewPartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final String expectedRoleName) {
        assertEquals(
                "'Roles which may view this partition' has unexpected selections",
                expectedRoleName,
                getApprovalStepPartitionRoleSelection(approvalStepIndex, approvalStepPartitionIndex, 1)
        );
    }

    /**
     * Asserts the element 'Approval Profile Type' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertApprovalProfileTypeIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Approval Profile Type' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_APPROVAL_PROFILE_TYPE)
        );
    }

    /**
     * Asserts the element 'Request Expiration Period' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertRequestExpirationPeriodIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Request Expiration Period' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_REQUEST_EXPIRATION_PERIOD)
        );
    }

    /**
     * Asserts the element 'Approval Expiration Period' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertApprovalExpirationPeriodIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Approval Expiration Period' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_APPROVAL_EXPIRATION_PERIOD)
        );
    }

    /**
     * Asserts the element 'Max Extension Time' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertMaxExtensionTimeIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Max Extension Time' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_MAX_EXTENSION_TIME)
        );
    }

    /**
     * Asserts the element 'Allow Self Approved Request Editing' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertAllowSelfApprovedRequestEditingIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Allow Self Approved Request Editing' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_ALLOW_SELF_APPROVED_REQUEST_EDITING)
        );
    }

    /**
     * Asserts the element partition's 'Name:' is enabled/disabled.
     *
     * @param approvalStepIndex approval step's index.
     * @param approvalStepPartitionIndex approval step's partition index.
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertApprovalStepPartitionNameIsEnabled(final int approvalStepIndex, final int approvalStepPartitionIndex, final boolean isEnabled) {
        assertEquals(
                "'Name' field [" + approvalStepIndex + ", " + approvalStepPartitionIndex + "] isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(
                        findElement(
                                getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex),
                                Page.INPUT_APPROVAL_STEP_PARTITION_NAME)
                )
        );
    }

    /**
     * Asserts the element partition's 'Roles which may approve this partition:' is enabled/disabled.
     *
     * @param approvalStepIndex approval step's index.
     * @param approvalStepPartitionIndex approval step's partition index.
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertApprovalStepPartitionApprovePartitionRoleIsEnabled(final int approvalStepIndex, final int approvalStepPartitionIndex, final boolean isEnabled) {
        assertEquals(
                "'Roles which may approve this partition' field [" + approvalStepIndex + ", " + approvalStepPartitionIndex + "] isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(getApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, 0))
        );
    }

    /**
     * Asserts the element partition's 'Roles which may view this partition:' is enabled/disabled.
     *
     * @param approvalStepIndex approval step's index.
     * @param approvalStepPartitionIndex approval step's partition index.
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertApprovalStepPartitionViewPartitionRoleIsEnabled(final int approvalStepIndex, final int approvalStepPartitionIndex, final boolean isEnabled) {
        assertEquals(
                "'Roles which may view this partition' field [" + approvalStepIndex + ", " + approvalStepPartitionIndex + "] isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(getApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, 1))
        );
    }

    /**
     * Asserts the approval profile name exists in the list.
     *
     * @param approvalProfileName approval profile name.
     */
    public void assertApprovalProfileNameExists(final String approvalProfileName) {
        assertElementExists(
                Page.getAPTableRowContainingText(approvalProfileName),
                approvalProfileName + " was not found on 'Approval Profiles' page."
        );
    }

    // Asserts the 'Approval Profile' name title exists.
    private void assertApprovalProfileTitleExists(final By textTitleId, final String prefixString, final String approvalProfileName) {
        final WebElement approvalProfileTitle = findElement(textTitleId);
        if(approvalProfileName == null) {
            fail("Approval Profile title was not found.");
        }
        assertEquals(
                "Action on wrong Approval Profile.",
                prefixString + approvalProfileName,
                approvalProfileTitle.getText()
        );
    }

    private WebElement getApprovalStepsTable() {
        return findElement(Page.TABLE_APPROVAL_STEPS);
    }

    private List<WebElement> getApprovalStepsRows() {
        return findElements(getApprovalStepsTable(), Page.TABLE_APPROVAL_STEPS_ROWS);
    }

    private WebElement getApprovalStepByIndex(final int approvalStepIndex) {
        return getApprovalStepByIndex(getApprovalStepsRows(), approvalStepIndex);
    }

    private WebElement getApprovalStepByIndex(final List<WebElement> approvalStepsRows, final int approvalStepIndex) {
        // Check for valid input and range
        if(approvalStepsRows != null && !approvalStepsRows.isEmpty() && (approvalStepIndex >= 0 && approvalStepIndex < approvalStepsRows.size())) {
            return approvalStepsRows.get(approvalStepIndex);
        }
        return null;
    }

    private List<WebElement> getApprovalStepPartitions(final int approvalStepIndex) {
        return getApprovalStepPartitions(getApprovalStepByIndex(approvalStepIndex));
    }

    private List<WebElement> getApprovalStepPartitions(final WebElement approvalStepRow) {
        // Check for valid input and range
        if(approvalStepRow != null) {
            return findElements(approvalStepRow, Page.TABLE_APPROVAL_STEP_PARTITIONS);
        }
        return null;
    }

    private WebElement getApprovalStepPartition(final int approvalStepIndex, final int approvalStepPartitionIndex) {
        final List<WebElement> approvalStepPartitions = getApprovalStepPartitions(approvalStepIndex);
        if(approvalStepPartitions != null && !approvalStepPartitions.isEmpty() && (approvalStepPartitionIndex >= 0 && approvalStepPartitionIndex < approvalStepPartitions.size())) {
            return approvalStepPartitions.get(approvalStepPartitionIndex);
        }
        return null;
    }

    private void addPartitionToApprovalStep(final int approvalStepIndex) {
        addPartitionToApprovalStep(getApprovalStepByIndex(approvalStepIndex));
    }

    private void addPartitionToApprovalStep(final WebElement approvalStep) {
        clickLink(findElement(approvalStep, Page.BUTTON_ADD_PARTITION));
    }

    private WebElement getApprovalStepPartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final int selectPartitionRoleIndex) {
        final WebElement approvalStepPartition = getApprovalStepPartition(approvalStepIndex, approvalStepPartitionIndex);
        final List<WebElement> selectPartitionRoles = findElements(approvalStepPartition, Page.SELECT_APPROVAL_STEP_PARTITION_ROLES_SELECT);
        return selectPartitionRoles.get(selectPartitionRoleIndex);
    }

    private void setApprovalStepPartitionRole(final int approvalStepIndex, final int approvalStepPartitionIndex, final int selectPartitionRoleIndex, final String roleName) {
        selectOptionByName(
                getApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, selectPartitionRoleIndex),
                roleName,
                true
        );
    }

    private int getApprovalStepPartitionRoleSelectionSize(final int approvalStepIndex, final int approvalStepPartitionIndex, final int selectPartitionRoleIndex) {
        final WebElement roleSelection = getApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, selectPartitionRoleIndex);
        return getSelectSelectedNames(roleSelection).size();
    }

    private String getApprovalStepPartitionRoleSelection(final int approvalStepIndex, final int approvalStepPartitionIndex, final int selectPartitionRoleIndex) {
        return getFirstSelectedOption(
                getApprovalStepPartitionRole(approvalStepIndex, approvalStepPartitionIndex, selectPartitionRoleIndex)
        );
    }
}
