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

    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;

    public static class TestData {
        private static final String ROOTCA_NAME = "ECAQA3";
        private static final String SUBCA_NAME = "subCA ECAQA3";
        private static final String ROOTCA_DN = "CN=ECAQA3,C=SE";
        private static final String SUBCA_DN = "CN=subCA3,C=SE";
        private static final String ROOTCA_VALIDITY = "1y";
        private static final String SUBCA_VALIDITY = "2y";
    }
    

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
        removeCaByName(TestData.SUBCA_NAME);
        // super
        afterClass();
    }

    @Test
    public void a_createRootCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.ROOTCA_NAME);

        // Set CA Type, Subject DN and Validity
        caHelper.setCaType(CaType.CVC);
        caHelper.setSubjectDn(TestData.ROOTCA_DN);
        caHelper.setValidity(TestData.ROOTCA_VALIDITY);

        // Save the CA and check that save was successful
        caHelper.createCa();
        caHelper.assertExists(TestData.ROOTCA_NAME);
    }

    @Test
    public void b_checkCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(TestData.ROOTCA_NAME);
    }

    @Test
    public void c_createSubCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.SUBCA_NAME);

        // Set CA Type, Crypto Token, Subject DN, Signed By, Validity and Certificate Profile
        caHelper.setCaType(CaType.CVC);
        caHelper.setCryptoToken(TestData.ROOTCA_NAME);
        caHelper.setSubjectDn(TestData.SUBCA_DN);
        caHelper.setSignedBy(TestData.ROOTCA_NAME);
        caHelper.setValidity(TestData.SUBCA_VALIDITY);
        caHelper.setCertificateProfile("SUBCA");

        // Save the CA and check that save was successful
        caHelper.createCa();
        caHelper.assertExists(TestData.SUBCA_NAME);
    }
}
