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
import org.ejbca.webtest.helper.CmpConfigurationHelper;
import org.ejbca.webtest.junit.MemoryTrackingTestRunner;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test attempts renaming of a CMP alias in the AdminGUI
 * 
 * @version $Id$
 */
@RunWith(MemoryTrackingTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa24_RenameCmpAlias extends WebTestBase {

    // Helpers
    private static CmpConfigurationHelper cmpConfigHelper;
    
    public static class TestData {
        static final String cmpAlias = "EcaQa24CmpAlias";
        static final String cmpAliasRenamed = "EcaQa24CmpAliasNew";
    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        cmpConfigHelper = new CmpConfigurationHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() {
        // Remove generated test data
        removeCmpAliasByName(TestData.cmpAlias);
        removeCmpAliasByName(TestData.cmpAliasRenamed);
        // super
        afterClass();
    }
    
    /**
     * Adds the alias. No assertions here. It is prerequisites.
     */
    @Test
    public void testA_createCmpAlias() {
        cmpConfigHelper.openPage(getAdminWebUrl());
        cmpConfigHelper.addCmpAlias(TestData.cmpAlias);
    }
    
    @Test
    public void testB_renameCmpAlias() {
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAlias);
        cmpConfigHelper.renameCmpAlias(TestData.cmpAlias, TestData.cmpAliasRenamed);
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAliasRenamed);
    }
}