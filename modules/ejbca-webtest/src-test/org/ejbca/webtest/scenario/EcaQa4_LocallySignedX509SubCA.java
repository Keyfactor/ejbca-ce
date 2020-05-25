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
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Web Test to verify that locally signing X509 SubCA work as expected.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-4>ECAQA-4</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa4_LocallySignedX509SubCA extends WebTestBase{

    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;
    
    // Test Data
    public static class TestData {
        static final String ALGORITH_AND_SPECIFICATION = "RSA 2048";
        static final String CA_NAME = "CA_ECAQA4";
        static final String CA_VALIDITY = "2y";
        static final String CRYPTOTOKEN_AUTH_CODE_FOO123 = "foo123";
        static final String CRYPTOTOKEN_TYPE_SOFT = "SOFT";
        static final String KEY_ALIAS = "ECAQA4KeyAlias";
        static final String SUBCA_CRYPTOTOKEN_NAME = "subCA_CryptoToken_ECAQA4";
        static final String SUBCA_NAME = "subCA_ECAQA4";
                
        static final boolean CRYPTOTOKEN_AUTOACTIVATION_TRUE = true;
    }
    
    @BeforeClass
    public static void init() {
    // Super
    beforeClass(true, null);
    final WebDriver webDriver = getWebDriver();
    // Helpers
    caHelper = new CaHelper(webDriver);
    cryptoTokenHelper = new CryptoTokenHelper(webDriver); 
    }
    
    @AfterClass
    public static void exit() {
        // Remove CA
        removeCaByName(TestData.CA_NAME);
        // Remove SubCA
        removeCaByName(TestData.SUBCA_NAME);
        // Remove CA CryptoToken
        removeCryptoTokenByCaName(TestData.CA_NAME);
        // Remove SubCA CryptoToken
        removeCryptoTokenByCaName(TestData.SUBCA_CRYPTOTOKEN_NAME);
        afterClass();
    }
    
    // Prerequisite (manual test is executed on appliance) 
    // Create SubCA CryptoToken
    @Test
    public void stepA_createSubCaCryptotoken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.openPageNewCryptoToken();
        cryptoTokenHelper.setNewCryptoTokenName(TestData.SUBCA_CRYPTOTOKEN_NAME);
        cryptoTokenHelper.setCryptoTokenType(TestData.CRYPTOTOKEN_TYPE_SOFT);
        cryptoTokenHelper.setTokenAuthCode(TestData.CRYPTOTOKEN_AUTH_CODE_FOO123);
        cryptoTokenHelper.setAutoActivation(TestData.CRYPTOTOKEN_AUTOACTIVATION_TRUE);
        cryptoTokenHelper.saveToken();
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(TestData.SUBCA_CRYPTOTOKEN_NAME);
    }
    
    // Create CA
    @Test
    public void stepB_createCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
    
    // Assert new CryptoToken
    @Test
    public void stepC_verifyNewCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(TestData.CA_NAME);
    }
    
    // Create SubCA CryptoToken key pair
    @Test
    public void stepD_createSubCaSignKey() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.openCryptoTokenPageByName(TestData.SUBCA_CRYPTOTOKEN_NAME);
        cryptoTokenHelper.generateKey(TestData.KEY_ALIAS, TestData.ALGORITH_AND_SPECIFICATION);
    }
    
    // Create and assert SubCA
    @Test
    public void stepE_createSubCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.SUBCA_NAME);
        caHelper.setCryptoToken(TestData.SUBCA_CRYPTOTOKEN_NAME);
        caHelper.setSignedBy(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.SUBCA_NAME);
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.SUBCA_NAME);
        caHelper.assertDefaultKeyValue(TestData.KEY_ALIAS);
    }
    
    // Asserts that no new CryptoToken was created for the SubCA
    @Test
    public void stepF_assertNoNewCrytoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(TestData.SUBCA_CRYPTOTOKEN_NAME);
        cryptoTokenHelper.assertTokenDoesNotExist(TestData.SUBCA_NAME);
    }
}
