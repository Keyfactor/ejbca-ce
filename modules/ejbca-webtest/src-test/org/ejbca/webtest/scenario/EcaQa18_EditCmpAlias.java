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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * In this test case the CMP alias 'ECAQA-18-CMPAlias' is edited.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-18">ECAQA-18</a>
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa18_EditCmpAlias extends WebTestBase {
       
    //Helpers
    private static CmpConfigurationHelper cmpConfigHelper;

    public static class TestData {
        static final String cmpAlias = "ECAQA-18-CMPAlias";
        static final String caName = "ManagementCA";
        static final String disabled = "(disabled)";
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
        // super
        afterClass();
    }

    /**
     * Add an alias and verify that the added alias exists .
     */
    @Test
    public void testA_createCmpAlias() {
        cmpConfigHelper.openPage(getAdminWebUrl());
        cmpConfigHelper.addCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAlias);
    }
    
    /**
     * Edit the alias and cancel.
     */
    @Test
    public void testB_cancelEditCmpAlias() {
        cmpConfigHelper.openPage(getAdminWebUrl());
        cmpConfigHelper.editCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.selectDefaultCA(TestData.caName);
        cmpConfigHelper.cancelEditCmpAlias();
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAlias);
        cmpConfigHelper.editCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.assertCmpAliasDefaultCA(TestData.disabled);
    }
    
    /**
     * Edit the alias and save.
     */
    @Test
    public void testC_saveEditCmpAlias() {
        cmpConfigHelper.openPage(getAdminWebUrl());
        cmpConfigHelper.editCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.selectDefaultCA(TestData.caName);
        cmpConfigHelper.saveEditCmpAlias();
        cmpConfigHelper.assertCmpAliasExists(TestData.cmpAlias);
        cmpConfigHelper.editCmpAlias(TestData.cmpAlias);
        cmpConfigHelper.assertCmpAliasDefaultCA(TestData.caName);
    }
}