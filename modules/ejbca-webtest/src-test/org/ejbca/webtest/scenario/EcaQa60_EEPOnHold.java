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
import java.util.Map;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.ejbca.webtest.junit.MemoryTrackingTestRunner;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * In this test case all possible fields of ENDUSER End Entity with End Entity Profile
 * 'OnHold' are filled in to verify that they work.
 *
 * @version $Id$
 */
@RunWith(MemoryTrackingTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa60_EEPOnHold extends WebTestBase {

    private static WebDriver webDriver;

    private static class TestData {
        private static final Map<String,String> INPUT_END_ENTITY_FIELDMAP = new HashMap<>();
        private static final Map<String,String> ASSERTION_FIELDMAP = new HashMap<>();
        
        private static final String EEP_NAME = "OnHold";
        private static final String EE_NAME = "TestEndEntityOnHold";
        private static final String EE_PASSWORD = "foo123";
        private static final String EEP_REVOCATION_REASON = "Suspended: Certificate Hold";
        private static final String EEP_REVOCATION_REASON_ADD_EE = "Suspended: Certificate hold";
        private static final String EEP_REVOCATION_REASON_CERTIFICATE_VIEW = "Revocation reasons : Certificate hold";
        private static final String EEP_TOKEN = "P12 file";
        
        // Map holding input fields and corresponding values
        static {
            INPUT_END_ENTITY_FIELDMAP.put("Username", EE_NAME);
            INPUT_END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", EE_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("Confirm Password", EE_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("CN, Common name", EE_NAME);
        }
        // Map holding input fields used for asserting existence
        static {
            ASSERTION_FIELDMAP.put("Username", null);
            ASSERTION_FIELDMAP.put("Password (or Enrollment Code)", null);
            ASSERTION_FIELDMAP.put("Confirm Password", null);
            ASSERTION_FIELDMAP.put("E-mail address", null);
            ASSERTION_FIELDMAP.put("CN, Common name", null);
        }
    }
    
    // Helpers
    private static AddEndEntityHelper addEeHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static SearchEndEntitiesHelper searchEeHelper;
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEeHelper = new AddEndEntityHelper(webDriver);
        eeProfileHelper = new EndEntityProfileHelper(webDriver);
        searchEeHelper = new SearchEndEntitiesHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeEndEntityByUsername(TestData.EE_NAME);
        removeEndEntityProfileByName(TestData.EEP_NAME);
        afterClass();
    }
    
    @Test
    public void testA_addAndEditEep() {
        eeProfileHelper.openPage(getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.EEP_NAME);
        eeProfileHelper.assertEndEntityProfileNameExists(TestData.EEP_NAME);
        eeProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);
        eeProfileHelper.triggerRevocationReasonSetAfterCertIssuance();
        eeProfileHelper.setIssuanceRevocationReason(TestData.EEP_REVOCATION_REASON);
        eeProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void testB_addEndEntity() {
        addEeHelper.openPage(getAdminWebUrl());
        addEeHelper.setEndEntityProfile(TestData.EEP_NAME);
        
        addEeHelper.assertFieldsExists(TestData.ASSERTION_FIELDMAP);
        addEeHelper.assertCertificateProfileSelected("ENDUSER");
        addEeHelper.assertTokenSelected("User Generated");
        addEeHelper.assertRevocationReasonSelected(TestData.EEP_REVOCATION_REASON_ADD_EE);
        
        addEeHelper.setCa(getCaName());
        addEeHelper.setToken(TestData.EEP_TOKEN);
        addEeHelper.fillFields(TestData.INPUT_END_ENTITY_FIELDMAP);

        addEeHelper.addEndEntity();
        addEeHelper.assertEndEntityAddedMessageDisplayed(TestData.EE_NAME);
    }

    @Test
    public void testC_verifyEndEntity() {
        searchEeHelper.openPage(getAdminWebUrl());
        searchEeHelper.switchViewModeFromAdvancedToBasic();
        searchEeHelper.fillSearchCriteria(TestData.EE_NAME, null, null, null);
        searchEeHelper.clickSearchByUsernameButton();
        searchEeHelper.assertNumberOfSearchResults(1);
        searchEeHelper.clickViewEndEntityForRow(TestData.EE_NAME);
        searchEeHelper.assertPopupContainsText(TestData.EEP_REVOCATION_REASON_ADD_EE);
    }

    @Test
    public void testD_enroll() {
        //TODO refactor in ECA-7710
        webDriver.get(getRaWebUrl() + "enrollwithusername.xhtml");
        webDriver.findElement(By.id("enrollWithUsernameForm:username")).sendKeys(TestData.EE_NAME);
        webDriver.findElement(By.id("enrollWithUsernameForm:enrollmentCode")).sendKeys(TestData.EE_PASSWORD);
        webDriver.findElement(By.id("enrollWithUsernameForm:checkButton")).click();
        webDriver.findElement(By.id("enrollWithUsernameForm:generatePkcs12")).click();
        
        searchEeHelper.openPage(getAdminWebUrl());
        searchEeHelper.fillSearchCriteria(TestData.EE_NAME, null, null, null);
        searchEeHelper.clickSearchByUsernameButton();
        searchEeHelper.assertNumberOfSearchResults(1);
        searchEeHelper.clickViewCertificateForRow(TestData.EE_NAME);
        searchEeHelper.assertPopupContainsText(TestData.EEP_REVOCATION_REASON_CERTIFICATE_VIEW);
    }
}
