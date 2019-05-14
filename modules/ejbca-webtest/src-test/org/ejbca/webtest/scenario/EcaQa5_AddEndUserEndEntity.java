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

import java.util.HashMap;

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
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<String, String>(); 
        fields.put("Username", "TestEndEnityEMPTY");
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.triggerBatchGeneration();
        
        addEndEntityHelper.fillFieldEmail("you_mail_box", "primekey.se");
    }
}
