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
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AdminRolesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import org.openqa.selenium.WebDriver;

/**
 * This test verifies the role template and access rules of Super Administrator template. In order to run the test, a Firefox profile
 * containing a superadmin certificate as first selection is required. The profile name can either be specified in /conf/profiles.properties
 * or a new Firefox profile can be created with the name 'superadmin'.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-78">ECAQA-78</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa78_SuperAdminAccess extends WebTestBase {

    // Helpers
    private static AdminRolesHelper adminRolesHelper;

    // Test Data
    public static class TestData {
        static final String ROLE_NAME = "Super Administrator Role";
        static final String TEXT_SUPER_ADMINISTRATORS = "Super Administrators";
        static final String TEXT_ALL_SELECTED = "All";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);//TODO ECA-7495 ConfigurationConstants.PROFILE_FIREFOX_SUPERADMIN);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        adminRolesHelper = new AdminRolesHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() {
        // super
        afterClass();
    }
    
    @Test
    public void stepA_verifyManageAdministratorRolesView() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.assertExistsMembersLinkForRole(TestData.ROLE_NAME);
        adminRolesHelper.assertExistsAccessRulesLinkForRole(TestData.ROLE_NAME);
        adminRolesHelper.assertExistsRenameButtonForRole(TestData.ROLE_NAME);
        adminRolesHelper.assertExistsDeleteButtonForRole(TestData.ROLE_NAME);
        adminRolesHelper.assertExistsAddRoleButton();
    }

    @Test
    public void stepB_verifyAccessRulesViewInBasicMode() {
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        // Check navigation links
        adminRolesHelper.assertExistsBackToAdministratorRolesLink();
        adminRolesHelper.assertExistsMembersLinkForRole();
        adminRolesHelper.assertExistsAdvancedModeLink();
        adminRolesHelper.assertExistsSaveButton();
        // Check select's status
        adminRolesHelper.assertRoleTemplateIsEnabled(true);
        adminRolesHelper.assertAuthorizedCAsIsEnabled(false);
        adminRolesHelper.assertEndEntityRulesIsEnabled(false);
        adminRolesHelper.assertEndEntityProfilesIsEnabled(false);
        adminRolesHelper.assertValidatorsIsEnabled(false);
        adminRolesHelper.assertInternalKeybindingRulesIsEnabled(false);
        adminRolesHelper.assertOtherRulesIsEnabled(false);
        // Check selects' values
        adminRolesHelper.assertRoleTemplateHasSelectedName(TestData.TEXT_SUPER_ADMINISTRATORS);
        adminRolesHelper.assertAuthorizedCAsHasSelectedName(TestData.TEXT_ALL_SELECTED);
        adminRolesHelper.assertEndEntityRulesHasAllSelected();
        adminRolesHelper.assertEndEntityProfilesHasSelectedName(TestData.TEXT_ALL_SELECTED);
        adminRolesHelper.assertValidatorsHasSelectedName(TestData.TEXT_ALL_SELECTED);
        adminRolesHelper.assertInternalKeybindingRulesHasAllSelected();
        adminRolesHelper.assertOtherRulesHasAllSelected();
    }

    @Test
    public void stepC_verifyAccessRulesView() {
        // Go to advanced mode
        adminRolesHelper.switchViewModeFromBasicToAdvanced();
        // Verify root ('/') is allowed 'ALLOW'
        adminRolesHelper.assertRuleCheckedRadioButtonsHasValue(0, 0, "ALLOW");
        // Remaining rules > 0 should have 'Inherit' checked with value 'UNDEFINED'
        adminRolesHelper.assertRuleCheckedRadioButtonsHasValue(1, Integer.MAX_VALUE, "UNDEFINED");
    }
}