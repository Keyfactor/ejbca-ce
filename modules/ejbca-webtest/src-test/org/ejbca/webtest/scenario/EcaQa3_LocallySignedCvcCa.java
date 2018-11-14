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
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

/**
 * Creates a self signed CVC CA using a dedicated Crypto Token.
 * 
 * @version $Id: EcaQa3_LocallySignedCvcCa.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa3_LocallySignedCvcCa extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;

    private static final String rootName = "ECAQA3";
    private static final String subName = "subCA ECAQA3";
    private static final String rootDn = "CN=ECAQA3,C=SE";
    private static final String subDn = "CN=subCA3,C=SE";

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
        // Remove generated artifacts
        removeCaAndCryptoToken(rootName);
        removeCaByName(subName);
        // super
        afterClass();
    }

    @Test
    public void a_createRootCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(rootName);

        // Set CA Type, Subject DN and Validity
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcatype']")))).selectByVisibleText("CVC");
        caHelper.setSubjectDn(rootDn);
        caHelper.setValidity("1y");

        // Save the CA and check that save was successful
        caHelper.saveCa();
        caHelper.assertExists(rootName);
    }

    @Test
    public void b_checkCryptoToken() {
        CryptoTokenHelper.goTo(webDriver, getAdminWebUrl());
        CryptoTokenHelper.assertExists(webDriver, rootName);
    }

    @Test
    public void c_createSubCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(subName);

        // Set CA Type, Crypto Token, Subject DN, Signed By, Validity and Certificate Profile
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcatype']")))).selectByVisibleText("CVC");
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcryptotoken']")))).selectByVisibleText(rootName);
        caHelper.setSubjectDn(subDn);
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectsignedby']")))).selectByVisibleText(rootName);
        caHelper.setValidity("2y");
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcertificateprofile']")))).selectByVisibleText("SUBCA");

        // Save the CA and check that save was successful
        caHelper.saveCa();
        caHelper.assertExists(subName);
    }
}