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

package org.ejbca.webtest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.WebTestBase;
import org.ejbca.helper.AuditLogHelper;
import org.ejbca.utils.WebTestUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * Tests Service Management according to the steps in ECAQA-28
 * @version $Id$
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa28_ServiceManagement extends WebTestBase {

    private static WebDriver webDriver;
    private static final String serviceName = "TestService";
    private static final String serviceRenamed = "FooService";
    private static final String serviceCloned = "BarService";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        webDriver.quit();
    }
    
    @Test
    public void testA_clickServiceLinkExpectPageLoad() {
        webDriver.get(getAdminWebUrl());
        webDriver.findElement(By.xpath("//li/a[contains(@href,'listservices.jsf')]")).click();
        assertEquals("Clicking 'Services' link did not redirect to expected page",
                WebTestUtils.getUrlIgnoreDomain(webDriver.getCurrentUrl()),
                "/ejbca/adminweb/services/listservices.jsf");
    }
    
    @Test
    public void testB_addServiceExpectAppendToList() {
        webDriver.findElement(By.xpath("//input[contains(@name, 'newServiceName')]")).sendKeys(serviceName);
        webDriver.findElement(By.xpath("//input[contains(@name, 'addButton')]")).click();
        assertIsServiceInList(serviceName, true);
    }
 
    @Test
    public void testC_editToCrlUpdaterExpectSaved() {
        final Select serviceList = new Select(webDriver.findElement(By.xpath("//select[@class='select-list']")));
        serviceList.selectByValue(serviceName);
        webDriver.findElement(By.xpath("//input[contains(@name, 'editButton')]")).click();
        final Select selectWorker = new Select(webDriver.findElement(By.xpath("//select[contains(@name, 'selectWorker')]")));
        selectWorker.selectByValue("CRLUPDATEWORKER");
        final Select selectWorkerUpdated = new Select(webDriver.findElement(By.xpath("//select[contains(@name, 'selectWorker')]")));
        assertEquals("CRL Updater was not selected", "CRL Updater", selectWorkerUpdated.getFirstSelectedOption().getText());
        webDriver.findElement(By.id("edit:saveButton")).click();
        
        assertIsServiceInList(serviceName, true);
    }
    
    @Test
    public void testD_renameServiceExpectNewNameInList() {
        final Select serviceList = new Select(webDriver.findElement(By.xpath("//select[@class='select-list']")));
        serviceList.selectByValue(serviceName);
        webDriver.findElement(By.xpath("//input[contains(@name, 'newServiceName')]")).sendKeys(serviceRenamed);
        webDriver.findElement(By.xpath("//input[contains(@name, 'renameButton')]")).click();
        assertIsServiceInList(serviceRenamed, true);
    }
    
    @Test
    public void testE_cloneServiceExpectNewInList() {
        final Select serviceList = new Select(webDriver.findElement(By.xpath("//select[@class='select-list']")));
        serviceList.selectByValue(serviceRenamed);
        webDriver.findElement(By.xpath("//input[contains(@name, 'newServiceName')]")).sendKeys(serviceCloned);
        webDriver.findElement(By.xpath("//input[contains(@name, 'cloneButton')]")).click();
        assertIsServiceInList(serviceCloned, true);
    }
    
    @Test
    public void testF_duplicateNameExpectFailure() {
        final Select serviceList = new Select(webDriver.findElement(By.xpath("//select[@class='select-list']")));
        serviceList.selectByValue(serviceCloned);
        webDriver.findElement(By.xpath("//input[contains(@name, 'newServiceName')]")).sendKeys(serviceRenamed);
        webDriver.findElement(By.xpath("//input[contains(@name, 'renameButton')]")).click();
        WebElement messageTable = webDriver.findElement(By.xpath("//table[@class='alert']"));
        assertEquals("No warning was given the service name already exists", "Service name already exists", messageTable.getText());
    }
    
    @Test
    public void testG_deleteServicesExpectRemovedFromList() throws InterruptedException {
        deleteService(serviceRenamed);
        Thread.sleep(1000); // Not pretty but WebDriverWait didn't work here for some reason.
        deleteService(serviceCloned);
        assertIsServiceInList(serviceRenamed, false);
        assertIsServiceInList(serviceCloned, false);
    }
    
    @Test
    public void testH_expectLogEvents() {
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.clearConditions(webDriver);
        AuditLogHelper.addCondition(webDriver, "Event", "Equals", "Service Add");
        AuditLogHelper.assertEntry(webDriver, "Service Add", "Success", null, null);
        
        AuditLogHelper.clearConditions(webDriver);
        AuditLogHelper.addCondition(webDriver, "Event", "Equals", "Service Edit");
        AuditLogHelper.assertEntry(webDriver, "Service Edit", "Success", null, null);
        
        AuditLogHelper.clearConditions(webDriver);
        AuditLogHelper.addCondition(webDriver, "Event", "Equals", "Service Remove");
        AuditLogHelper.assertEntry(webDriver, "Service Remove", "Success", null, null);
    }
    
    private void deleteService(String serviceName) {
        WebDriverWait wait = new WebDriverWait(webDriver, 3);
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.xpath("//select[@class='select-list']")));
        try {
            final Select serviceList = new Select(webDriver.findElement(By.xpath("//select[@class='select-list']")));
            serviceList.selectByValue(serviceName);
        } catch (NoSuchElementException e) {
            fail("Failed to delete service: Could not find the service '" + serviceName + "' in the list of services");
        } finally {
            // Delete the alias
            webDriver.findElement(By.xpath("//input[contains(@name, 'deleteButton')]")).click();;
            Alert alert = webDriver.switchTo().alert();
            alert.accept();
        }
    }
    
    /**
     * Checks whether a service exists in the list of services
     * @param serviceName name to check for
     * @param assertInList true if expected to be in list
     */
    private void assertIsServiceInList(String serviceName, boolean assertInList) {
        WebElement serviceList = webDriver.findElement(By.xpath("//select[contains(@name, 'listServices')]"));
        try {
            serviceList.findElement(By.xpath("//option[@value='" + serviceName + "']"));
        } catch (NoSuchElementException e) {
            if (assertInList) {
                fail(serviceName + " was not found in the List of Services");
            } else {
                return;
            }
        }
        if (!assertInList) {
            fail(serviceName + " was still in the list of services after deleting it");
        }
    }
}
