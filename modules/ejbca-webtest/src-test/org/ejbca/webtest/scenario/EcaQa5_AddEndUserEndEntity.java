package org.ejbca.webtest.scenario;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

public class EcaQa5_AddEndUserEndEntity extends WebTestBase {
    private static WebDriver webDriver;

    // Helpers
    private static AddEndEntityHelper addEndEntityHelper;

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
        webDriver = getWebDriver();
        // Init helpers
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
        removeCaByName(TestData.SUBCA_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_AddEndEntityProfile() {
        addEndEntityHelper.openPage(getAdminWebUrl());
    }
}
