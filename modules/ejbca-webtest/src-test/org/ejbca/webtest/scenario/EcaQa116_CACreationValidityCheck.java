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

import org.apache.commons.lang.StringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

/**
 * Check that CA could be created with different Validity formats.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-116">ECAQA-116</a>
 * 
 * @version $Id$
 */
public class EcaQa116_CACreationValidityCheck extends WebTestBase {
    
    // Helpers
    private static CaHelper caHelper;
    
    // Test Data
    private static class TestData {
        static final String CA_NAME = "ECAQA-116-TestCA";
        static final String CA_VALIDITY_EMPTY = StringUtils.EMPTY;
        static final String CA_VALIDITY_BAD_FORMAT = "blabla";
        static final String INVALID_SAN_ERROR = "Error: Invalid validity or certificate end time: Illegal characters.";
        static final String EMPTY_SAN_ERROR = "Ca Validity: Validation Error: Value is required.";
        static final String GOOD_VALIDITY_SHORT_FORMAT = "2y";
        static final String GOOD_VALIDITY_LONG_FORMAT = "2024-10-01";
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

    @After
    public void clean(){
        removeCaAndCryptoToken(TestData.CA_NAME);
    }
    
    @Test
    public void addCaWithInvalidValidity() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY_BAD_FORMAT);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INVALID_SAN_ERROR);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);        
    }
    
    @Test
    public void addCaWithEmptyValidity() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY_EMPTY);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.EMPTY_SAN_ERROR);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);        
    }
    
    @Test
    public void addCaWithGoodValidityShortFormat() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.GOOD_VALIDITY_SHORT_FORMAT);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
    
    @Test
    public void addCaWithGoodValidityLongFormat() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.GOOD_VALIDITY_LONG_FORMAT);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }    
    
}
