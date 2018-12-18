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

import org.cesecore.authorization.AuthorizationDeniedException;
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
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa72_CaNameChange extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static SystemConfigurationHelper sysConfigHelper;
    private static final String caName = "ECAQA72CA";

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Initialize helpers
        caHelper = new CaHelper(webDriver);
        sysConfigHelper = new SystemConfigurationHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        removeCaByName(caName);
        // super
        afterClass();
    }
    
    @Test
    public void testA_addCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(caName);
        // Set validity (required)
        caHelper.setValidity("1y");
        caHelper.createCa();
        caHelper.assertExists(caName);
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
        caHelper.edit(caName);
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
        caHelper.edit(caName);
        caHelper.assertCheckboxcaNameChangePresent();
        caHelper.assertNewSubjectDnIsEnabled(false);
    }
    
    @Test
    public void testF_changeCaDn() {
        caHelper.checkUseCaNameChange();
        caHelper.assertNewSubjectDnIsEnabled(true);
    }
}