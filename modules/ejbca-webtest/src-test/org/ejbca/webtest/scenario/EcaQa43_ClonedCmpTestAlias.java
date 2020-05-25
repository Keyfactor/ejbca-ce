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
 * In this test case the CMP alias 'CmpTestAlias' is cloned into the alias 'ClonedCmpTestAlias'. Then it is checked
 * if all the values from 'CmpTestAlias' were copied to 'ClonedCmpTestAlias'.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-43">ECAQA-43</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa43_ClonedCmpTestAlias extends WebTestBase {
       
    //Helpers
    private static CmpConfigurationHelper cmpConfigHelper;

    public static class TestData {
        static final String cmpAlias = "EcaQa43CmpAlias";
        static final String cloneCmpAlias = "EcaQa43CloneCmpAlias";
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
        removeCmpAliasByName(TestData.cloneCmpAlias);
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
     * Clone an alias and verify that the cloned alias exists .
     */
    @Test
    public void testB_cloneCmpAlias() {
        cmpConfigHelper.cloneCmpAlias(TestData.cmpAlias, TestData.cloneCmpAlias);
        cmpConfigHelper.assertCmpAliasExists(TestData.cloneCmpAlias);
    }
}
