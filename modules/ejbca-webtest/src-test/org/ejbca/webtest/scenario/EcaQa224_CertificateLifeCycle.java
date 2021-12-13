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

import java.util.Collections;
import java.util.HashMap;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.RaWebUseUsernameRequestHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test checks the Certificate Details page in RA Web.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-244">ECAQA-244</a>
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa224_CertificateLifeCycle extends WebTestBase {

    // Classes used.
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static RaWebUseUsernameRequestHelper raWebUseUsernameRequestHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper; 
    private static AuditLogHelper auditLogHelper;

    // Test Data
    public static class TestData {
        static final String END_ENTITY_NAME = "EcaQa224TestUser";
        static final String END_ENTITY_PASSWORD = "foo123";
        static final String END_ENTITY_COMMON_NAME = "EcaQa224TestUser";
        static final String END_ENTITY_TOKEN = "JKS file";
        static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
        static final String CA_NAME = "ManagementCA";
        static final String KEY_ALGORITHM = "RSA 2048 bits";
    }
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        raWebUseUsernameRequestHelper = new RaWebUseUsernameRequestHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
        auditLogHelper.initFilterTime();
    }
    
    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        cleanup();
        afterClass();
    }
    
    @Test
    public void testA_AddEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", TestData.END_ENTITY_PASSWORD);
        fields.put("Confirm Password", TestData.END_ENTITY_PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setToken(TestData.END_ENTITY_TOKEN);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(TestData.CA_NAME);
        addEndEntityHelper.addEndEntity();
    }
    
    @Test
    public void testB_RaWeb() {
        raWebUseUsernameRequestHelper.openPage(getRaWebUrl());
        // Use sleep to find next element.
        try {
            Thread.sleep(200);

        } catch (InterruptedException e) {
              // NOPMD
        }
        raWebUseUsernameRequestHelper.clickToEnrollUseUsername();
        raWebUseUsernameRequestHelper.fillEnrollUsernameAndCode(TestData.END_ENTITY_NAME, TestData.END_ENTITY_PASSWORD);
        raWebUseUsernameRequestHelper.clickCheckButton();
        raWebUseUsernameRequestHelper.selectKeyAlgorithm(TestData.KEY_ALGORITHM);
        raWebUseUsernameRequestHelper.clickEnrollDownloadPKCS12Button();
    }
    
    @Test
    public void testC_SearchEndEntities() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
    }
    
    @Test
    public void testD_RevokeTestUser(){
        searchEndEntitiesHelper.chooseFromRevocationReason("Certificate hold");
        searchEndEntitiesHelper.triggerSearchResultFirstRowSelect();
        searchEndEntitiesHelper.clickRevokeSelected();
        searchEndEntitiesHelper.acceptAlert();
    }
    
    @Test
    public void testE_ReactivateCertificate() {
        searchEndEntitiesHelper.clickViewCertificateForRow(TestData.END_ENTITY_COMMON_NAME);
        String mainWindow = webDriver.getWindowHandle();
        searchEndEntitiesHelper.switchToPopup();
        searchEndEntitiesHelper.clickReactive();
        searchEndEntitiesHelper.acceptAlert();
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    @Test
    public void testF_CheckReactiveBtnIsAvailible() {
        searchEndEntitiesHelper.clickViewCertificateForRow(TestData.END_ENTITY_COMMON_NAME);
        String mainWindow = webDriver.getWindowHandle();
        searchEndEntitiesHelper.switchToPopup();
        searchEndEntitiesHelper.assertReactiveButtonNotPresent();
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    @Test
    public void testG_AuditLogEndEntityAddedInDetails() {
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertAddEndEntityLogExists(TestData.END_ENTITY_NAME);
    }
    
    @Test
    public void testH_AuditLogEndEntityRevokeInDetails() {
        auditLogHelper.assertRevokeEndEntityLogExists(TestData.END_ENTITY_NAME);
    }
    
    @Test
    public void testI_AuditLogEndEntityCertHoldInDetails() {
        String certificateHoldTextt = auditLogHelper.getCertificateOnHoldRecordText(TestData.END_ENTITY_NAME);
        auditLogHelper.assertLogEntryByEventText("Certificate Revoke", "Success", null,
                Collections.singletonList(certificateHoldTextt));
    }
    
    @Test
    public void testJ_AuditLogEndEntityRevokeCertInDetails() {
        // Only checking 'Event' log by username.
        auditLogHelper.setViewFilteringCondition("Username", "Equals", TestData.END_ENTITY_NAME);
        auditLogHelper.assertLogEntryByEventText("Certificate Revoke", "Success", null,null);
    }
    
    private static void cleanup() {
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeCertificateByUsername(TestData.END_ENTITY_NAME);
    }

}
