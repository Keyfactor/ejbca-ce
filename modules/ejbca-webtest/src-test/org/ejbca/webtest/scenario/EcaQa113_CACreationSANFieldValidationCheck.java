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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * CA creation SAN field validation check.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-113">ECAQA-113</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa113_CACreationSANFieldValidationCheck extends WebTestBase {

    // Helpers
    private static CaHelper caHelper;

    // Test Data
    private static class TestData {
        static final String CA_NAME = "ECAQA-113-TestCA";
        static final String CA_VALIDITY = "2y";
        static final String INVALID_SAN = "blabla";
        static final String INVALID_SAN_SPACE = "DNS Name=www.example.com";
        static final String VALID_SAN = "DNSName=www.example.com";
        static final String INVALID_SAN_ERROR = "Error: Creation of CA failed, invalid Subject Alternative Name (example of correct SAN: DNSName=www.example.com)";
    }
    
    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
    }
    
    @AfterClass
    public static void exit(){
        removeCaAndCryptoToken(TestData.CA_NAME);
        // super
        afterClass();
    }

    @Test
    public void addCaWithInvalidSAN() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setSubjectAlternativeName(TestData.INVALID_SAN);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INVALID_SAN_ERROR);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);
    }
    
    @Test
    public void addCaWithInvalidSANSpace() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setSubjectAlternativeName(TestData.INVALID_SAN_SPACE);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INVALID_SAN_ERROR);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);
    }
    
    @Test
    public void addCaWithValidSAN() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setSubjectAlternativeName(TestData.VALID_SAN);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
}
