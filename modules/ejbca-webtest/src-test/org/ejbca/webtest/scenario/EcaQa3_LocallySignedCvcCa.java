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
import org.ejbca.webtest.helper.CaHelper.CaType;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Creates a self signed CVC CA using a dedicated Crypto Token.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa3_LocallySignedCvcCa extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;

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
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
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
        caHelper.setCaType(CaType.CVC);
        caHelper.setSubjectDn(rootDn);
        caHelper.setValidity("1y");

        // Save the CA and check that save was successful
        caHelper.createCa();
        caHelper.assertExists(rootName);
    }

    @Test
    public void b_checkCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(rootName);
    }

    @Test
    public void c_createSubCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(subName);

        // Set CA Type, Crypto Token, Subject DN, Signed By, Validity and Certificate Profile
        caHelper.setCaType(CaType.CVC);
        caHelper.setCryptoToken(rootName);
        caHelper.setSubjectDn(subDn);
        caHelper.setSignedBy(rootName);
        caHelper.setValidity("2y");
        caHelper.setCertificateProfile("SUBCA");

        // Save the CA and check that save was successful
        caHelper.createCa();
        caHelper.assertExists(subName);
    }
}
