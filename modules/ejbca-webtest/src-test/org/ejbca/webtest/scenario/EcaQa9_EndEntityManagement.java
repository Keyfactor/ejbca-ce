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
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.HashMap;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa9_EndEntityManagement extends WebTestBase {

    //Classes
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static AuditLogHelper auditLogHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;


    //Test Data
    public static class TestData {
        static String END_ENTITY_NAME = "EcaQa9TestEndEntity";
        static String END_ENTITY_COMMON_NAME = "EcaQa9 Test CN";
        static String END_ENTITY_PROFILE_NAME = "EMPTY";
        static String PASSWORD = "foo123";
        static String NEW_PASSWORD = "1q2w3e4r";
        static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
        static final String CA_NAME = "ManagementCA";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
        auditLogHelper.initFilterTime();
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        cleanup();
        afterClass();
    }

    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
    }

    //@Test
    public void testA_addEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", TestData.PASSWORD);
        fields.put("Confirm Password", TestData.PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(TestData.CA_NAME);
        addEndEntityHelper.addEndEntity();
    }

    //@Test
    public void testB_checkAuditLogAddRecord(){
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertAddEndEntityLogExists(TestData.END_ENTITY_NAME);
    }

    //@Test
    public void testC_checkSearchEndEntity(){
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic();
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);

    }

    //@Test
    public void testC_editEndEntity(){
        searchEndEntitiesHelper.clickEditEndEntityForRow(TestData.END_ENTITY_COMMON_NAME);
        String mainWindow = webDriver.getWindowHandle();
        searchEndEntitiesHelper.switchToPopup();
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Password (or Enrollment Code)", TestData.NEW_PASSWORD);
        fields.put("Confirm Password", TestData.NEW_PASSWORD);
        searchEndEntitiesHelper.fillEndEntityEditFields(fields);
        searchEndEntitiesHelper.saveEndEntity();
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }

    //@Test
    public void testD_checkAuditLogEditRecord(){
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertEditEndEntityLogExists(TestData.END_ENTITY_NAME);
    }

    //@Test
    public void testE_revokeEndEntity(){
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic();
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.triggerSearchResultUsernameRowSelect(TestData.END_ENTITY_COMMON_NAME);
        searchEndEntitiesHelper.clickRevokeSelected();
        searchEndEntitiesHelper.acceptAlert();
    }

    //@Test
    public void testF_checkAuditLogRevokeRecord(){
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertRevokeEndEntityLogExists(TestData.END_ENTITY_NAME);
    }

    //@Test
    public void testG_deleteEndEntity(){
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic();
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.triggerSearchResultUsernameRowSelect(TestData.END_ENTITY_COMMON_NAME);
        searchEndEntitiesHelper.clickDeleteSelected();
        // Are you sure you want to delete selected end entities?
        searchEndEntitiesHelper.acceptAlert();
        // Are the selected end entities revoked?
        searchEndEntitiesHelper.acceptAlert();
        searchEndEntitiesHelper.reload();
        searchEndEntitiesHelper.assertNoSearchResults();
    }

    //@Test
    public void testH_checkAuditLogRemoveRecord(){
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertRemoveEndEntityLogExists(TestData.END_ENTITY_NAME);
    }

    @Test
    public void emty(){
        //empty test to avoid java.lang.Exception: No runnable methods
        //remove when test fixed
    }
}
