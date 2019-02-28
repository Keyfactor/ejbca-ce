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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;
import java.util.List;

/**
 * Helper class for handling 'Roles and Access Rules' page in automated web tests.
 *
 * @version $Id$
 */
public class AdminRolesHelper extends BaseHelper {

    private ViewMode viewContext = null;

    public enum ViewMode {
        VIEW_MODE_BASIC, VIEW_MODE_ADVANCED,
        VIEW_MODE_MEMBERS
    }

    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/administratorprivileges/roles.xhtml";
        static final By PAGE_LINK = By.id("sysFuncsRoles");
        // Manage Roles and Access Rules
        static final By BUTTON_ADD = By.id("roles:list:addRoleButton");
        static final By INPUT_MODAL_ROLE_NAME = By.id("modal:roleNameInputField");
        static final By BUTTON_MODAL_ADD = By.id("modal:confirmAddRoleButton");
        // Form Access Rules
        static final By BUTTON_BACK_TO_ADMINISTRATOR_ROLES = By.id("backToAdministratorRoles");
        static final String TEXT_VIEW_MODE_SWITCH_MEMBERS = "Members";
        static final String TEXT_VIEW_MODE_SWITCH_ROLE_MEMBERS = "View Role Members";
        static final By BUTTON_VIEW_MODE_MEMBERS_OR_ROLE_MEMBERS = By.id("viewMembers");
        static final String TEXT_VIEW_MODE_SWITCH_BASIC = "Basic Mode";
        static final String TEXT_VIEW_MODE_SWITCH_ADVANCED = "Advanced Mode";
        static final By BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED = By.id("viewModeSwitchBasicOrAdvanced");
        static final By BUTTON_VIEW_MODE_SWITCH_CONFIG_OR_SUMMARY = By.id("viewModeSwitchConfigOrSummary");
        static final By TEXT_TITLE_ROLE = By.id("titleRole");
        static final By TABLES_ACCESS_RULES = By.xpath("//td/table[@class='fullwidth']");
        static final By CELL_ACCESS_RULE_GROUP_NAME = By.xpath(".//thead/tr/th");
        static final By CELL_ACCESS_RULE_TEXT = By.xpath(".//td[@class='rulesColumn1 alignmiddle']");
        static final By CELL_ACCESS_RULE_RADIO_BUTTONS = By.xpath(".//td[@class='rulesColumn2 alignmiddle']/table[@class='selectStateRadio']");
        static final By TABLES_ACCESS_RULE_RADIO_BUTTONS = By.xpath("//table[@class='selectStateRadio']");
        static final By INPUT_ACCESS_RULE_RADIO_BUTTONS = By.xpath(".//input[@type='radio']");
        static final By INPUT_ACCESS_RULE_RADIO_BUTTON_CHECKED = By.xpath(".//input[@checked='checked']");
        /**
         * Basic view / 'Role Template'
         */
        static final By SELECT_ROLE_TEMPLATE = By.id("accessRulesForm:selectrole");
        /**
         * Basic view / 'Authorized CAs'
         */
        static final By SELECT_AUTHORIZED_CAS = By.id("accessRulesForm:selectcas");
        /**
         * Basic view / 'End Entity Rules'
         */
        static final By SELECT_END_ENTITY_RULES = By.id("accessRulesForm:selectendentityrules");
        /**
         * Basic view / 'End Entity Profiles'
         */
        static final By SELECT_END_ENTITY_PROFILES = By.id("accessRulesForm:selectendentityprofiles");
        /**
         * Basic view / 'Validators'
         */
        static final By SELECT_VALIDATORS = By.id("accessRulesForm:selectkeyvalidators");
        /**
         * Basic view / 'Internal Keybinding Rules'
         */
        static final By SELECT_INTERNAL_KEYBINDING_RULES = By.id("accessRulesForm:selectinternalkeybindingrules");
        /**
         * Basic view / 'Other Rules'
         */
        static final By SELECT_OTHER_RULES = By.id("accessRulesForm:selectother");
        static final By BUTTON_SAVE_VIEW_MODE_BASIC = By.id("accessRulesForm:basicModeSave");
        static final By BUTTON_SAVE_VIEW_MODE_ADVANCED = By.id("accessRulesForm:advancedRulesTable:advancedModeSave");
        // Members Form
        static final By SELECT_MATCH_WITH = By.id("rolemembers:list:matchWith");
        static final By SELECT_CA = By.id("rolemembers:list:caId");
        static final By INPUT_MATCH_VALUE = By.id("rolemembers:list:tokenMatchValue");
        static final By BUTTON_MEMBER_ADD = By.xpath("//*[@id='rolemembers:list:actionBlock']/input[@value='Add']");

        // Dynamic references' parts
        static final String TABLE_ROLES = "//*[@id='roles:list']";
        static final String TABLE_MEMBERS = "//*[@id='rolemembers:list']/tbody";

        // Dynamic references
        static By getRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']");
        }
        static By getMemebersButtonFromRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']/../td/a[text()='Members']");
        }
        static By getAccessRulesButtonFromRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']/../td/a[text()='Access Rules']");
        }
        static By getRenameButtonFromRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']/../td/div/input[@value='Rename']");
        }
        static By getDeleteButtonFromRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']/../td/div/input[@value='Delete']");
        }

        static By getMatchWithFromMembersTableRowContainingText(final String text) {
            return By.xpath(TABLE_MEMBERS + "/tr/td[text()='" + text + "']");
        }
    }

    public AdminRolesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Roles and Access Rules' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a role.
     *
     * @param roleName role name.
     */
    public void addRole(final String roleName) {
        clickLink(Page.BUTTON_ADD);
        fillInput(Page.INPUT_MODAL_ROLE_NAME, roleName);
        clickLink(Page.BUTTON_MODAL_ADD);
        assertRoleAdded();
        assertRoleNameExists(roleName);
    }

    /**
     * Clicks 'Members' for the role.
     *
     * @param roleName role name.
     */
    public void openEditMembersPage(final String roleName) {
        // Click 'Access Rules' of the role
        clickLink(Page.getMemebersButtonFromRolesTableRowContainingText(roleName));
        // Assert correct edit page
        assertRoleTitleExists( "Administrator Role : ", roleName);
        // Set context
        viewContext = ViewMode.VIEW_MODE_MEMBERS;
    }

    /**
     * Clicks 'Access Rules' for the role.
     *
     * @param roleName role name.
     */
    public void openEditAccessRulesPage(final String roleName) {
        // Click 'Access Rules' of the role
        clickLink(Page.getAccessRulesButtonFromRolesTableRowContainingText(roleName));
        // Assert correct edit page
        assertRoleTitleExists( "Administrator Role : ", roleName);
        // Set context
        viewContext = ViewMode.VIEW_MODE_BASIC;
    }

    /**
     * Selects 'Role Template' by name.
     *
     * @param roleTemplateName template name.
     */
    public void selectRoleTemplate(final String roleTemplateName) {
        if(viewContext == ViewMode.VIEW_MODE_BASIC) {
            selectOptionByName(Page.SELECT_ROLE_TEMPLATE, roleTemplateName);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    public void selectMatchWith(final String matchWith) {
        if(viewContext == ViewMode.VIEW_MODE_MEMBERS) {
            selectOptionByName(Page.SELECT_MATCH_WITH, matchWith);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    public void selectCa(final String ca) {
        if(viewContext == ViewMode.VIEW_MODE_MEMBERS) {
            selectOptionByName(Page.SELECT_CA, ca);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    public void setMatchValue(final String matchValue) {
        if(viewContext == ViewMode.VIEW_MODE_MEMBERS) {
            fillInput(Page.INPUT_MATCH_VALUE, matchValue);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    public void clickAddMember() {
        if(viewContext == ViewMode.VIEW_MODE_MEMBERS) {
            clickLink(Page.BUTTON_MEMBER_ADD);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    /**
     * Switches the view to 'Advanced Mode' if the link with proper text exists.
     * <br/>
     * Changes the viewContext of this instance to ViewMode.VIEW_MODE_ADVANCED.
     */
    public void switchViewModeFromBasicToAdvanced() {
        if(Page.TEXT_VIEW_MODE_SWITCH_ADVANCED.equals(getElementText(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED))) {
            clickLink(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED);
            viewContext = ViewMode.VIEW_MODE_ADVANCED;
        }
    }

    /**
     * Clicks 'Save' button and asserts the update info message displayed.
     */
    public void saveAccessRule() {
        if(viewContext == ViewMode.VIEW_MODE_BASIC) {
            clickLink(Page.BUTTON_SAVE_VIEW_MODE_BASIC);
        }
        else if(viewContext == ViewMode.VIEW_MODE_ADVANCED) {
            clickLink(Page.BUTTON_SAVE_VIEW_MODE_ADVANCED);
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
        assertRoleUpdated();
    }

    /**
     * Asserts the group of access rules' values are sorted in ascending order.
     */
    public void assertAllAccessRuleStringsAreSortedAsc() {
        final List<WebElement> accessRuleGroups = findElements(Page.TABLES_ACCESS_RULES);
        assertNotNull("Acess rule groups list is null", accessRuleGroups);
        assertFalse("Access rule groups are empty.", accessRuleGroups.isEmpty());
        // Check elements
        for (WebElement accessRuleGroup : accessRuleGroups) {
            final String accessRuleGroupName = findElement(accessRuleGroup, Page.CELL_ACCESS_RULE_GROUP_NAME).getText();
            final List<String> accessRuleGroupTexts = getAccessRuleTexts(accessRuleGroup);
            final List<String> sortedAccessRuleGroupTexts = new ArrayList<>(accessRuleGroupTexts);
            sortedAccessRuleGroupTexts.sort(String::compareToIgnoreCase);
            assertEquals("'" + accessRuleGroupName + "' group was not sorted alphabetically.", sortedAccessRuleGroupTexts, accessRuleGroupTexts);
        }
    }

    /**
     * Asserts the link 'Members' exists.
     *
     * @param roleName role name.
     */
    public void assertExistsMembersLinkForRole(final String roleName) {
        assertElementExists(
                Page.getMemebersButtonFromRolesTableRowContainingText(roleName),
                "Link 'Members' does not exist for '" + roleName + "'.");
    }

    /**
     * Asserts the link 'Access Rules' exists.
     *
     * @param roleName role name.
     */
    public void assertExistsAccessRulesLinkForRole(final String roleName) {
        assertElementExists(
                Page.getAccessRulesButtonFromRolesTableRowContainingText(roleName),
                "Link 'Access Rules' does not exist for '" + roleName + "'.");
    }

    /**
     * Asserts the button 'Rename' exists.
     *
     * @param roleName role name.
     */
    public void assertExistsRenameButtonForRole(final String roleName) {
        assertElementExists(
                Page.getRenameButtonFromRolesTableRowContainingText(roleName),
                "Button 'Rename' does not exist for '" + roleName + "'.");
    }

    /**
     * Asserts the button 'Delete' exists.
     *
     * @param roleName role name.
     */
    public void assertExistsDeleteButtonForRole(final String roleName) {
        assertElementExists(
                Page.getDeleteButtonFromRolesTableRowContainingText(roleName),
                "Button 'Delete' does not exist for '" + roleName + "'.");
    }

    /**
     * Asserts the button 'Add' exists.
     */
    public void assertExistsAddRoleButton() {
        assertElementExists(Page.BUTTON_ADD, "Button 'Add' does not exist.");
    }

    /**
     * Asserts the link 'Back to Roles and Access Rules' exists.
     */
    public void assertExistsBackToAdministratorRolesLink() {
        assertElementExists(Page.BUTTON_BACK_TO_ADMINISTRATOR_ROLES, "Link 'Back to Role Management' does not exist.");
    }

    /**
     * Asserts the link 'Members' exists.
     */
    public void assertExistsMembersLinkForRole() {
        assertElementExists(Page.BUTTON_VIEW_MODE_MEMBERS_OR_ROLE_MEMBERS, "Link 'Members' does not exist.");
        assertEquals("Link 'Members' has different text.", Page.TEXT_VIEW_MODE_SWITCH_MEMBERS, getElementText(Page.BUTTON_VIEW_MODE_MEMBERS_OR_ROLE_MEMBERS));
    }

    /**
     * Asserts the link 'Advanced Mode' exists.
     */
    public void assertExistsAdvancedModeLink() {
        assertElementExists(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED, "Link 'Advanced Mode' does not exist.");
        assertEquals("Link 'Advanced Mode' has different text.", Page.TEXT_VIEW_MODE_SWITCH_ADVANCED, getElementText(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED));
    }

    /**
     * Asserts the button 'Save' exists.
     */
    public void assertExistsSaveButton() {
        if(viewContext == ViewMode.VIEW_MODE_BASIC) {
            assertElementExists(Page.BUTTON_SAVE_VIEW_MODE_BASIC, "Button 'Save' does not exist.");
        }
        else if(viewContext == ViewMode.VIEW_MODE_ADVANCED) {
            assertElementExists(Page.BUTTON_SAVE_VIEW_MODE_ADVANCED, "Button 'Save' does not exist.");
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    /**
     * Asserts the element 'Role Template' has selected name.
     *
     * @param name selected name.
     */
    public void assertRoleTemplateHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_ROLE_TEMPLATE);
        assertNotNull("'Role Template' was not found", selectedNames);
        assertTrue("'Role Template' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'End Entity Rules' has selected name.
     *
     * @param name selected name.
     */
    public void assertAuthorizedCAsHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_AUTHORIZED_CAS);
        assertNotNull("'Authorized CAs' was not found", selectedNames);
        assertTrue("'Authorized CAs' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'Authorized CAs' has all selected.
     */
    public void assertEndEntityRulesHasAllSelected() {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_END_ENTITY_RULES);
        final List<String> allNames = getSelectValues(Page.SELECT_END_ENTITY_RULES);
        assertNotNull("'End Entity Rules' was not found", selectedNames);
        assertNotNull("'End Entity Rules' was not found", allNames);
        assertEquals("'End Entity Rules' selection mismatch - not all selected", selectedNames.size(), allNames.size());
    }

    /**
     * Asserts the element 'End Entity Profiles' has selected name.
     *
     * @param name selected name.
     */
    public void assertEndEntityProfilesHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_END_ENTITY_PROFILES);
        assertNotNull("'End Entity Profiles' was not found", selectedNames);
        assertTrue("'End Entity Profiles' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'Validators' has selected name.
     *
     * @param name selected name.
     */
    public void assertValidatorsHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_VALIDATORS);
        assertNotNull("'Validators' was not found", selectedNames);
        assertTrue("'Validators' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'Internal Keybinding Rules' has all selected.
     */
    public void assertInternalKeybindingRulesHasAllSelected() {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_INTERNAL_KEYBINDING_RULES);
        final List<String> allNames = getSelectValues(Page.SELECT_INTERNAL_KEYBINDING_RULES);
        assertNotNull("'Internal Keybinding Rules' was not found", selectedNames);
        assertNotNull("'Internal Keybinding Rules' was not found", allNames);
        assertEquals("'Internal Keybinding Rules' selection mismatch - not all selected", selectedNames.size(), allNames.size());
    }

    /**
     * Asserts the element 'Other Rules' has all selected.
     */
    public void assertOtherRulesHasAllSelected() {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_OTHER_RULES);
        final List<String> allNames = getSelectValues(Page.SELECT_OTHER_RULES);
        assertNotNull("'Other Rules' was not found", selectedNames);
        assertNotNull("'Other Rules' was not found", allNames);
        assertEquals("'Other Rules' selection mismatch - not all selected", selectedNames.size(), allNames.size());
    }

    /**
     * Asserts the element 'Role Template' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertRoleTemplateIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Role Template' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_ROLE_TEMPLATE)
        );
    }

    /**
     * Asserts the element 'Authorized CAs' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertAuthorizedCAsIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Authorized CAs' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_AUTHORIZED_CAS)
        );
    }

    /**
     * Asserts the element 'End Entity Rules' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertEndEntityRulesIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'End Entity Rules' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_END_ENTITY_RULES)
        );
    }

    /**
     * Asserts the element 'End Entity Profiles' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertEndEntityProfilesIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'End Entity Profiles' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_END_ENTITY_PROFILES)
        );
    }

    /**
     * Asserts the element 'Validators' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertValidatorsIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Validators' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_VALIDATORS)
        );
    }

    /**
     * Asserts the element 'Internal Keybinding Rules' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertInternalKeybindingRulesIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Internal Keybinding Rules' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_INTERNAL_KEYBINDING_RULES)
        );
    }

    /**
     * Asserts the element 'Other Rules' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertOtherRulesIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Other Rules' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_OTHER_RULES)
        );
    }

    /**
     * Asserts that radio buttons by given range in array of radio buttons have the value.
     *
     * @param startIndex start index in array of checked radio buttons.
     * @param endIndex end index (inclusive) in array of checked radio buttons.
     * @param value the value of a radio button.
     */
    public void assertRuleCheckedRadioButtonsHasValue(final int startIndex, final int endIndex, final String value) {
        if(viewContext == ViewMode.VIEW_MODE_ADVANCED) {
            final List<WebElement> radioButtonContainers = findElements(Page.TABLES_ACCESS_RULE_RADIO_BUTTONS);
            if(!radioButtonContainers.isEmpty()) {
                int rangeMaximum = Math.min(radioButtonContainers.size()-1, endIndex);
                assertTrue("startIndex ["+ startIndex +"] has to be less or equal to possible maximum [" + rangeMaximum + "]", startIndex <= rangeMaximum);
                for (int index = startIndex; index <= rangeMaximum; index++) {
                    final WebElement rootContainer = radioButtonContainers.get(index);
                    final WebElement checkedRadioButton = findElement(rootContainer, Page.INPUT_ACCESS_RULE_RADIO_BUTTON_CHECKED);
                    assertNotNull("Cannot find checked radio button for group [" + index + "]", checkedRadioButton);
                    assertEquals("Value mismatch for checked radio button at [" + index + "]", value, getElementValue(checkedRadioButton));
                }
            }
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    /**
     * Asserts that the members row with a given text exists.
     *
     * @param matchWith a text of a row.
     */
    public void assertMemberMatchWithRowExists(final String matchWith) {
        assertElementExists(
                Page.getMatchWithFromMembersTableRowContainingText(matchWith),
                "'" + matchWith + "' was not found on 'Members' page."
        );
    }

    /**
     * Triggers the access radio button by its value (ALLOW, DENY, UNDEFINED) for the given access path.
     *
     * @param rulePath access rule path.
     * @param value radio button's trigger value (ALLOW, DENY, UNDEFINED).
     */
    public void setRuleCheckedRadioButton(final String rulePath, final String value) {
        if(viewContext == ViewMode.VIEW_MODE_ADVANCED) {
            boolean found = false;
            int accessRulePathRowIndex = 0;
            // Access Rule Groups
            final List<WebElement> accessRuleGroups = findElements(Page.TABLES_ACCESS_RULES);
            for (WebElement accessRuleGroup : accessRuleGroups) {
                // Access Rule Groups' path
                final List<WebElement> accessRuleRows = findElements(accessRuleGroup, Page.CELL_ACCESS_RULE_TEXT);
                for (WebElement accessRuleRow : accessRuleRows) {
                    final String accessRuleRowText = accessRuleRow.getText();
                    if(rulePath.equals(accessRuleRowText)) {
                        int accessRuleButtonsRowIndex = 0;
                        // Access Rule Groups' Radio Buttons Tables
                        final List<WebElement> radioButtonsTables = findElements(accessRuleGroup, Page.CELL_ACCESS_RULE_RADIO_BUTTONS);
                        for (WebElement radioButtonsTable : radioButtonsTables) {
                            if(accessRulePathRowIndex == accessRuleButtonsRowIndex) {
                                final List<WebElement> radioButtons = findElements(radioButtonsTable, Page.INPUT_ACCESS_RULE_RADIO_BUTTONS);
                                for(WebElement radioButton : radioButtons) {
                                    final String radioButtonContainerValue = getElementValue(radioButton);
                                    if (value.equals(radioButtonContainerValue)) {
                                        radioButton.click();
                                        found = true;
                                        break;
                                    }
                                }
                            }
                            if(found) {
                                break;
                            }
                            accessRuleButtonsRowIndex++;
                        }
                    }
                    if(found) {
                        break;
                    }
                    accessRulePathRowIndex++;
                }
                accessRulePathRowIndex = 0;
                if(found) {
                    break;
                }
            }
            if(!found) {
                fail("Please check your test scenario action, this action cannot be applied.");
            }
        }
        else {
            fail("Please check your test scenario action, this action cannot be applied.");
        }
    }

    // Asserts the 'Manage Administrator Roles' add title exists.
    private void assertRoleAdded() {
        assertInfoMessageAppears("Role added.",
                "Expected role add message was not displayed.",
                "Role add message was not found.");
    }

    // Asserts the 'Manage Administrator Roles' update title exists.
    private void assertRoleUpdated() {
        assertInfoMessageAppears("Role updated successfully.",
                "Expected role update message was not displayed.",
                "Role update message was not found.");
    }

    // Asserts the 'Manage Administrator Roles' name exists.
    private void assertRoleNameExists(final String roleName) {
        assertElementExists(
                Page.getRolesTableRowContainingText(roleName),
                roleName + " was not found on 'Manage Administrator Roles' page."
        );
    }

    // Asserts the 'Administrator Role' name title exists.
    private void assertRoleTitleExists(final String prefixString, final String roleName) {
        if(roleName == null) {
            fail("Role cannot be null.");
        }
        final WebElement roleTitle = findElement(Page.TEXT_TITLE_ROLE);
        assertEquals(
                "Action on wrong role.",
                prefixString + roleName,
                roleTitle.getText()
        );
    }

    // Returns Access Rule Texts for the specific group represented by root element
    private List<String> getAccessRuleTexts(final WebElement rootElement) {
        final List<String> textsList = new ArrayList<>();
        final List<WebElement> accessRuleRows = findElements(rootElement, Page.CELL_ACCESS_RULE_TEXT);
        for (WebElement accessRuleRow : accessRuleRows) {
            textsList.add(accessRuleRow.getText());
        }
        return textsList;
    }

}
