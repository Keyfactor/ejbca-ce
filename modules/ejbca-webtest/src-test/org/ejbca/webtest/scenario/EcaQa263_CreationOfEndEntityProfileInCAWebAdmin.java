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
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa263_CreationOfEndEntityProfileInCAWebAdmin extends WebTestBase {
    
    //Helpers
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static WebDriver webDriver;

    //TestData
    private static final String ENTITY_PROFILE_NAME = "ChaEntityProfile";
    private static final String DEFAULT_CA_NAME = "Example Person CA";

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        afterClass();

    }

    @Test
    public void testA_AddEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(ENTITY_PROFILE_NAME);
        endEntityProfileHelper.openEditEndEntityProfilePage(ENTITY_PROFILE_NAME);
        endEntityProfileHelper.triggerEndEntityEmailCheckBox();
        
    }

    
    @Test
    public void testB_AddAttributes() {
        endEntityProfileHelper.addSubjectDnAttribute("O, Organization");
        endEntityProfileHelper.subjectDnAttributeRequiredBoxTrigger("O, Organization");
        endEntityProfileHelper.addSubjectDnAttribute("C, Country (ISO 3166)");
        endEntityProfileHelper.subjectDnAttributeRequiredBoxTrigger("C, Country (ISO 3166)");
    }

    @Test
    public void testC_DefaultCaAndSave() {
        endEntityProfileHelper.selectDefaultCa(DEFAULT_CA_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        endEntityProfileHelper.deleteEndEntityProfile(ENTITY_PROFILE_NAME);
        endEntityProfileHelper.confirmEndEntityProfileDeletion(true);
    }
}
