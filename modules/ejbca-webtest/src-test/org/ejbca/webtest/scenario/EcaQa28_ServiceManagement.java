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
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.ServicesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

// TODO Current scenario depends on the success of previous steps, thus, may limit/complicate the discovery of other problems by blocking data prerequisites for next steps. Improve isolation of test data and flows?
/**
 * Tests Service Management according to the steps in ECAQA-28
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-28">ECAQA-28</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa28_ServiceManagement extends WebTestBase {

    // Helpers
    private static ServicesHelper servicesHelper;
    private static AuditLogHelper auditLogHelper;
    // Test Data
    private static class TestData {
        private static final String SERVICE_NAME = "ECAQA-28-Service";
        private static final String SERVICE_NAME_RENAMED = "ECAQA-28-Service-Renamed";
        private static final String SERVICE_NAME_CLONED = "ECAQA-28-Service-Cloned";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        servicesHelper = new ServicesHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // super
        afterClass();
    }

    @Test
    public void stepA_addServiceExpectAppendToList() {
        auditLogHelper.initFilterTime();
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.addService(TestData.SERVICE_NAME);
        // Assert Service exists
        servicesHelper.assertServiceNameExists(TestData.SERVICE_NAME);
    }
 
    @Test
    public void stepB_editToCrlUpdaterExpectSaved() {
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.openEditServicePage(TestData.SERVICE_NAME);
        servicesHelper.editService("CRL Updater");
        servicesHelper.assertWorkerHasSelectedName("CRL Updater");
        servicesHelper.saveService();
        // Assert Service exists
        servicesHelper.assertServiceNameExists(TestData.SERVICE_NAME);
    }
    
    @Test
    public void stepC_renameServiceExpectNewNameInList() {
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.renameService(TestData.SERVICE_NAME, TestData.SERVICE_NAME_RENAMED);
        // Assert Old Service does not exist, and new one exists
        servicesHelper.assertServiceNameDoesNotExist(TestData.SERVICE_NAME);
        servicesHelper.assertServiceNameExists(TestData.SERVICE_NAME_RENAMED);
    }
    
    @Test
    public void stepD_cloneServiceExpectNewInList() {
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.cloneService(TestData.SERVICE_NAME_RENAMED, TestData.SERVICE_NAME_CLONED);
        // Assert both service exist
        servicesHelper.assertServiceNameExists(TestData.SERVICE_NAME_RENAMED);
        servicesHelper.assertServiceNameExists(TestData.SERVICE_NAME_CLONED);
    }
    
    @Test
    public void stepE_duplicateNameExpectFailure() {
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.renameService(TestData.SERVICE_NAME_CLONED, TestData.SERVICE_NAME_RENAMED);
        servicesHelper.assertHasErrorMessage("Service name already exists");
    }
    
    @Test
    public void stepF_deleteServicesExpectRemovedFromList() throws InterruptedException {
        servicesHelper.openPage(getAdminWebUrl());
        servicesHelper.deleteService(TestData.SERVICE_NAME_RENAMED);
        servicesHelper.confirmServiceDeletion(null, true);
        // TODO Review after JSP->JSF conversion
        Thread.sleep(2000); // Not pretty but WebDriverWait didn't work here for some reason.
        servicesHelper.assertServiceNameDoesNotExist(TestData.SERVICE_NAME_RENAMED);
        servicesHelper.deleteService(TestData.SERVICE_NAME_CLONED);
        servicesHelper.confirmServiceDeletion(null, true);
        // TODO Review after JSP->JSF conversion
        Thread.sleep(2000); // Not pretty but WebDriverWait didn't work here for some reason.
        servicesHelper.assertServiceNameDoesNotExist(TestData.SERVICE_NAME_CLONED);
    }
    
    @Test
    public void testG_expectLogEvents() {
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Service Add",
                "Success",
                null,
                null
        );
        auditLogHelper.assertLogEntryByEventText(
                "Service Edit",
                "Success",
                null,
                null
        );
        auditLogHelper.assertLogEntryByEventText(
                "Service Remove",
                "Success",
                null,
                null
        );
    }

}
