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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * 
 * @version $Id: EcaQa72_CaNameChange.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa72_CaNameChange extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static final String caName = "ECAQA72CA";

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        removeCaByName(caName);
        // super
        afterClass();
    }
    
    private void editNameChangeGlobalConfig(boolean saveAsEnabled) {
        // TODO refactor  ECA-7360
        webDriver.findElement(By.xpath("//div/a[contains(@href,'systemconfiguration.xhtml')]")).click();
        WebElement checkboxEnableNameChange = webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange"));
        if ((!checkboxEnableNameChange.isSelected() && saveAsEnabled) || (checkboxEnableNameChange.isSelected() && !saveAsEnabled)) {
            checkboxEnableNameChange.click();
            webDriver.findElement(By.xpath("//input[@value='Save']")).click();
        }
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
        editNameChangeGlobalConfig(false);
        assertFalse("Failed to disable 'Enable CA Name Change'", webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange")).isSelected());
    }

    @Test
    public void testC_editCaExpectNoNameChangeAvailable() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(caName);
        caHelper.assertCheckboxcaNameChangeNotPresent();
        caHelper.assertNewSubjectDnNotPresent();
    }
    
    @Test
    public void testD_enableNameChange() {
        editNameChangeGlobalConfig(true);
        assertTrue("Failed to enable'Enable CA Name Change'", webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange")).isSelected());
    }
    
    @Test
    public void testE_editCaExpectNameChangeAvailable() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(caName);
        try {
            caHelper.assertCheckboxcaNameChangePresent();
            caHelper.assertNewSubjectDnIsEnabled(false);
        } catch (NoSuchElementException e) {
            fail("'Use CA Name Change' was not available while editing the CA even though it was globally enabled");
        }
    }
    
    @Test
    public void testF_changeCaDn() {
        caHelper.checkUseCaNameChange();
        caHelper.assertNewSubjectDnIsEnabled(true);
    }
}