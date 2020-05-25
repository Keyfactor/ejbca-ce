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
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigTabs;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test will test configuration option 'Enable CA Name Change' that can enable or disable CA Name Change feature
 * during CA renewal which should be used only for ICAO CSCA.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-72">ECAQA-72</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa72_CaNameChange extends WebTestBase {

    // Helpers
    private static CaHelper caHelper;
    private static SystemConfigurationHelper sysConfigHelper;

    public static class TestData {
        private static final String CA_NAME = "ECAQA72CA";
        private static final String CA_VALIDITY = "1y";
    }
    
    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Initialize helpers
        caHelper = new CaHelper(webDriver);
        sysConfigHelper = new SystemConfigurationHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() {
        removeCaByName(TestData.CA_NAME);
        // super
        afterClass();
    }
    
    @Test
    public void testA_addCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        // Set validity (required)
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
    
    @Test
    public void testB_disableNameChange() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SysConfigTabs.BASICCONFIG);
        sysConfigHelper.triggerEnableCaNameChange(false);
        sysConfigHelper.saveBasicConfiguration();
        sysConfigHelper.assertEnableCaNameChangeIsEnabled(false);
    }

    @Test
    public void testC_editCaExpectNoNameChangeAvailable() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertCheckboxCaNameChangeNotPresent();
        caHelper.assertNewSubjectDnNotPresent();
    }
    
    @Test
    public void testD_enableNameChange() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SysConfigTabs.BASICCONFIG);
        sysConfigHelper.triggerEnableCaNameChange(true);
        sysConfigHelper.saveBasicConfiguration();
        sysConfigHelper.assertEnableCaNameChangeIsEnabled(true);
    }
    
    @Test
    public void testE_editCaExpectNameChangeAvailable() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertCheckboxcaNameChangePresent();
        caHelper.assertNewSubjectDnIsEnabled(false);
    }
    
    @Test
    public void testF_changeCaDn() {
        caHelper.checkUseCaNameChange();
        caHelper.assertNewSubjectDnIsEnabled(true);
    }
}