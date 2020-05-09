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
import org.ejbca.webtest.junit.MemoryTrackingTestRunner;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * In 'advanced mode' for 'Access Rules' the content should be sorted by name alphabetically. This makes it
 * rather easier to review the access rules or locate the appropriate access rules you want to set.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-67">ECAQA-67</a>
 *
 * @version $Id$
 */
@RunWith(MemoryTrackingTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa67_AccessRuleSorted extends WebTestBase {

    // Helpers
    private static AdminRolesHelper adminRolesHelper;

    // Test Data
    public static class TestData {
        static final String ROLE_NAME = "ECAQA67_TestRole";
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
        // Remove generated artifacts
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        // super
        afterClass();
    }
    
    @Test
    public void stepA_addRoleAndEditRules() {
        // Add Role
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.switchViewModeFromBasicToAdvanced();
    }
    
    @Test
    public void stepB_assertAccessRulesOrdering() {
        adminRolesHelper.assertAllAccessRuleStringsAreSortedAsc();
    }

}