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
import org.ejbca.webtest.helper.AcmeHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa183_AddACMEAlias extends WebTestBase {
   
    //Helpers
    private static AcmeHelper acmeHelper;
    private static WebDriver webDriver;
    
    //Test Data
    private static final String ACME_ALIAS = "Test"; 
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        acmeHelper = new AcmeHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void testA_AddAcme() {
       acmeHelper.openPage(getAdminWebUrl());
       acmeHelper.clickAdd();
       acmeHelper.addTextToAlertTextfieldAndAccept(ACME_ALIAS); 
    }
   
    @Test
    public void testB_AddSameAcmeAgain() {
        acmeHelper.clickAdd();
        acmeHelper.addTextToAlertTextfieldAndAccept(ACME_ALIAS);
        acmeHelper.confirmAliasAlreadyExist(ACME_ALIAS);
    }
    
    @Test
    public void testC_AddAcmeAliasWithoutName() throws Exception {
        acmeHelper.clickAdd();
        acmeHelper.addTextToAlertTextfieldAndAccept("");
        acmeHelper.deleteWithName(ACME_ALIAS);
        acmeHelper.acceptAlert();
    }
}
