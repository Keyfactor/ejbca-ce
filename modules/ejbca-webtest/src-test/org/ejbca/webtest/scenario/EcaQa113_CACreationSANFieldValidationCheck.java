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
 * 
 * @version $Id$
 *
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
    }
    
    @Test
    public void addCaWithInvalidSANSpace() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setSubjectAlternativeName(TestData.INVALID_SAN_SPACE);
        caHelper.createCa();
        caHelper.assertHasErrorMessage(TestData.INVALID_SAN_ERROR);
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
