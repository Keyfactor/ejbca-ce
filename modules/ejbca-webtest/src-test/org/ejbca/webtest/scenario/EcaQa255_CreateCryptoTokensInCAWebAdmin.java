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
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa255_CreateCryptoTokensInCAWebAdmin extends WebTestBase {
    //Helpers
    private static WebDriver webDriver;
    private static CryptoTokenHelper cryptoTokenHelper;

    //TestData
    private static final String TOKEN_NAME = "CHARootCrypto";
    private static final String KEY_NAME_DEFAULTKEY = "defaultKey";
    private static final String KEY_NAME_SIGNKEY = "signkey";
    private static final String KEY_NAME_TESTKEY = "testkey";

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeCryptoTokenByCaName(TOKEN_NAME);
        afterClass();
    }

    @Test
    public void testA_CreateCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.openPageNewCryptoToken();
        cryptoTokenHelper.setNewCryptoTokenName(TOKEN_NAME);
        cryptoTokenHelper.setCryptoTokenType("SOFT");
        cryptoTokenHelper.setTokenAuthCode("100");
        cryptoTokenHelper.setAutoActivation(true);
        cryptoTokenHelper.saveToken();
    }

    @Test
    public void testB_GenerateKeys() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.viewCryptoTokenWithName("CHARootCrypto");
        cryptoTokenHelper.generateKey(KEY_NAME_DEFAULTKEY, "RSA 1024");
        cryptoTokenHelper.generateKey(KEY_NAME_SIGNKEY, "RSA 1024");
        cryptoTokenHelper.generateKey(KEY_NAME_TESTKEY, "RSA 1024");
    }

    @Test
    public void testE_TestGeneratedKeys() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.viewCryptoTokenWithName("CHARootCrypto");
        
        cryptoTokenHelper.clickTestKryptoToken(KEY_NAME_DEFAULTKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(KEY_NAME_DEFAULTKEY);
        
        cryptoTokenHelper.clickTestKryptoToken(KEY_NAME_SIGNKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(KEY_NAME_SIGNKEY);
        
        cryptoTokenHelper.clickTestKryptoToken(KEY_NAME_TESTKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(KEY_NAME_TESTKEY);
    }
}
