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
import static org.junit.Assert.fail;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.ArrayList;
import java.util.List;

/**
 * Helper class for handling 'Administrator Roles' page in automated web tests.
 *
 * @version $Id: AdminRolesHelper.java 30446 2018-11-09 10:16:38Z andrey_s_helmes $
 */
public class AdminRolesHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/administratorprivileges/roles.xhtml";
        static final By PAGE_LINK = By.id("sysFuncsRoles");
        //
        static final By BUTTON_ADD = By.id("roles:list:addRoleButton");
        static final By TEXT_MESSAGE = By.xpath("//*[@id='messages']//li[@class='infoMessage']");
        static final By INPUT_MODAL_ROLE_NAME = By.id("modal:roleNameInputField");
        static final By BUTTON_MODAL_ADD = By.id("modal:confirmAddRoleButton");
        // Form
//        static final String TEXT_VIEW_MODE_SWITCH_BASIC = "Basic Mode";
        static final String TEXT_VIEW_MODE_SWITCH_ADVANCED = "Advanced Mode";
        static final By BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED = By.id("viewModeSwitchBasicOrAdvanced");
//        static final By BUTTON_VIEW_MODE_SWITCH_CONFIG_OR_SUMMARY = By.id("viewModeSwitchConfigOrSummary");
        static final By TEXT_TITLE_ROLE = By.id("titleRole");
        static final By TABLES_ACCESS_RULES = By.xpath("//td/table[@class='fullwidth']");
        static final By CELL_ACCESS_RULE_GROUP_NAME = By.xpath(".//thead/tr/th");
        static final By CELL_ACCESS_RULE_TEXT = By.xpath(".//td[@class='rulesColumn1 alignmiddle']");
        // Dynamic references' parts
        static final String TABLE_ROLES = "//*[@id='roles:list']";
        // Dynamic references
        static By getRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']");
        }
        static By getAccessRulesButtonFromRolesTableRowContainingText(final String text) {
            return By.xpath(TABLE_ROLES + "//tr/td[text()='" + text + "']/../td[3]/a[text()='Access Rules']");
        }
    }

    public AdminRolesHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'Administrator Roles' by clicking menu link on home page and asserts the correctness of resulting URI.
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
     * Clicks 'Access Rules' for the role.
     *
     * @param roleName role name.
     */
    public void openEditAccessRulesPage(final String roleName) {
        // Click 'Access Rules' of the role
        clickLink(Page.getAccessRulesButtonFromRolesTableRowContainingText(roleName));
        // Assert correct edit page
        assertRoleTitleExists( "Administrator Role : ", roleName);
    }

    /**
     * Switches the view to 'Advanced Mode' if the link with proper text exists.
     */
    public void switchViewModeFromBasicToAdvanced() {
        if(Page.TEXT_VIEW_MODE_SWITCH_ADVANCED.equals(getElementText(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED))) {
            clickLink(Page.BUTTON_VIEW_MODE_SWITCH_BASIC_OR_ADVANCED);
        }
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

    // Asserts the 'Manage Administrator Roles' add title exists.
    private void assertRoleAdded() {
        final WebElement roleAddMessage = findElement(Page.TEXT_MESSAGE);
        if(roleAddMessage == null) {
            fail("Role add message was not found.");
        }
        assertEquals(
                "Expected role add message was not displayed.",
                "Role added.",
                roleAddMessage.getText()
        );
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
