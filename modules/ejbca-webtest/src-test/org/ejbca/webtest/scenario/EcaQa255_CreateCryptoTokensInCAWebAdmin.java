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

/**
 * This test verifies generated token in CA Web Admin.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-255">ECAQA-255</a>
 * 
 * @version $Id$: EcaQa255_CreateCryptoTokensInCAWebAdmin.java 2020-04-21 15:00 tobiasM$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa255_CreateCryptoTokensInCAWebAdmin extends WebTestBase {

    // Helpers
    private static CryptoTokenHelper cryptoTokenHelper;

    // TestData
    public static class TestData {
        static final String TOKEN_NAME = "EcaQa255Token";
        static final String CRYPTOTOKEN_TYPE_SOFT = "SOFT";
        static final String KEY_NAME_DEFAULTKEY = "defaultKey";
        static final String KEY_NAME_SIGNKEY = "signkey";
        static final String KEY_NAME_TESTKEY = "testkey";
        
        static final String KEY_SPECIFICATION = "RSA 1024";
    }
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        cryptoTokenHelper = new CryptoTokenHelper(getWebDriver());
    }

    @AfterClass
    public static void exit() {
        removeCryptoTokenByCaName(TestData.TOKEN_NAME);
        afterClass();
    }

    @Test
    public void stepA_CreateCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.openPageNewCryptoToken();
        cryptoTokenHelper.setNewCryptoTokenName(TestData.TOKEN_NAME);
        cryptoTokenHelper.setCryptoTokenType(TestData.CRYPTOTOKEN_TYPE_SOFT);
        cryptoTokenHelper.setTokenAuthCode("100");
        cryptoTokenHelper.setAutoActivation(true);
        cryptoTokenHelper.saveToken();
    }

    @Test
    public void stepB_GenerateKeys() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.viewCryptoTokenWithName(TestData.TOKEN_NAME);
        cryptoTokenHelper.generateKey(TestData.KEY_NAME_DEFAULTKEY, TestData.KEY_SPECIFICATION);
        cryptoTokenHelper.generateKey(TestData.KEY_NAME_SIGNKEY, TestData.KEY_SPECIFICATION);
        cryptoTokenHelper.generateKey(TestData.KEY_NAME_TESTKEY, TestData.KEY_SPECIFICATION);
    }

    @Test
    public void stepE_TestGeneratedKeys() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.viewCryptoTokenWithName(TestData.TOKEN_NAME);
        //
        cryptoTokenHelper.clickTestCryptoTokenAlias(TestData.KEY_NAME_DEFAULTKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(TestData.KEY_NAME_DEFAULTKEY);
        //
        cryptoTokenHelper.clickTestCryptoTokenAlias(TestData.KEY_NAME_SIGNKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(TestData.KEY_NAME_SIGNKEY);
        //
        cryptoTokenHelper.clickTestCryptoTokenAlias(TestData.KEY_NAME_TESTKEY);
        cryptoTokenHelper.confirmKeyTestedSuccessfully(TestData.KEY_NAME_TESTKEY);
    }
}