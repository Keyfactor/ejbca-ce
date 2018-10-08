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
package org.ejbca.webtest;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
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
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa72_CaNameChange extends WebTestBase {

    private static CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
 
    private static final String caName = "ECAQA72CA";
    private static WebDriver webDriver;
    
    
    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        CAInfo caInfo = caSession.getCAInfo(admin, caName);
        if (caInfo != null) {
            caSession.removeCA(admin, caInfo.getCAId());
        }
        webDriver.quit();
    }
    
    private void editNameChangeGlobalConfig(boolean saveAsEnabled) {
        webDriver.findElement(By.xpath("//li/a[contains(@href,'systemconfiguration.jsf')]")).click();
        WebElement checkboxEnableNameChange = webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange"));
        if ((!checkboxEnableNameChange.isSelected() && saveAsEnabled) || (checkboxEnableNameChange.isSelected() && !saveAsEnabled)) {
            checkboxEnableNameChange.click();
            webDriver.findElement(By.xpath("//input[@value='Save']")).click();
        }
    }
    
    @Test
    public void testA_addCa() {
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.add(webDriver, caName);
        // Set validity (required)
        CaHelper.setValidity(webDriver, "1y");
        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, caName);
    }
    
    @Test
    public void testB_disableNameChange() {
        editNameChangeGlobalConfig(false);
        assertFalse("Failed to disable 'Enable CA Name Change'", webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange")).isSelected());
    }
    
    @Test
    public void testC_editCaExpectNoNameChangeAvailable() {
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.edit(webDriver, caName);
        try {
            webDriver.findElement(By.id("idcheckboxcanamechange"));
            webDriver.findElement(By.id("idnewsubjectdn"));
            fail("'Use CA Name Change' was available while editing the CA even though it was globally disabled");
        } catch (NoSuchElementException e) {
            // Expected
        }
    }
    
    @Test
    public void testD_enableNameChange() {
        editNameChangeGlobalConfig(true);
        assertTrue("Failed to enable'Enable CA Name Change'", webDriver.findElement(By.id("systemconfiguration:enableicaocanamechange")).isSelected());
    }
    
    @Test
    public void testE_editCaExpectNameChangeAvailable() {
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.edit(webDriver, caName);
        try {
            webDriver.findElement(By.id("idcheckboxcanamechange"));
            WebElement newDn = webDriver.findElement(By.id("idnewsubjectdn"));
            assertFalse("'New Subject DN' was enabled by default", newDn.isEnabled());
        } catch (NoSuchElementException e) {
            fail("'Use CA Name Change' was not available while editing the CA even though it was globally enabled");
        }
    }
    
    @Test
    public void testF_changeCaDn() {
        webDriver.findElement(By.id("idcheckboxcanamechange")).click();
        WebElement newDn = webDriver.findElement(By.id("idnewsubjectdn"));
        assertTrue("'New Subject DN' was enabled by default", newDn.isEnabled());
    }
}