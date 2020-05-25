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
import java.util.List;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * This test checks the Certificate Details page in RA Web.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-244">ECAQA-244</a>
 *
 * @version $Id: EcaQa244_CertificateLifeCycle.java 31450 2019-02-08 15:46:45Z samuellb $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa244_CertificateLifeCycle extends WebTestBase {

    // Classes used.
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static RaWebHelper raWebHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper; 
    private static AuditLogHelper auditLogHelper;
    
    private static final String END_ENTITY_NAME = "TestUser";
    private static final String END_ENTITY_PASSWORD = "foo123";
    private static final String END_ENTITY_COMMON_NAME = "TestUser";
    private static final String END_ENTITY_TOKEN = "JKS file";
    private static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
    private static final By REACTIVE_BTN_XPATH = By.xpath("//input[@value=\"Reactivate\"]");
    private static final By AUDITLOG_DETAILS_ADDED_XPATH = By.xpath("//span[contains(text(),'Added end entity " + END_ENTITY_NAME + "')]");
    private static final By AUDITLOG_DETAILS_REVOKED_XPATH = By.xpath("//td[contains(text(),'Revoked end entity " + END_ENTITY_NAME + ".')]");
    private static final By AUDITLOG_DETAILS_CERTIFICATEHOLD_XPATH = By.xpath("//span[contains(@title,\"Activated certificate on hold for username '" + END_ENTITY_NAME + "'\")]");

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
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
        fields.put("Username", END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", END_ENTITY_PASSWORD);
        fields.put("Confirm Password", END_ENTITY_PASSWORD);
        fields.put("CN, Common name", END_ENTITY_COMMON_NAME);
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setToken(END_ENTITY_TOKEN);
        addEndEntityHelper.setCertificateProfile(CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.addEndEntity();
    }
    
    @Test
    public void testB_RaWeb() {
        raWebHelper.openPage(getRaWebUrl());
        // Use sleep to find next element.
        try {
            Thread.sleep(200);

        } catch (InterruptedException e) {
              // NOPMD
        }
        raWebHelper.clickToEnrollUseUsername(webDriver);
        raWebHelper.fillEnrollUsernameAndCode(END_ENTITY_NAME, END_ENTITY_PASSWORD);
        raWebHelper.clickCheck();
        raWebHelper.clickEnrollDownloadPKCS12Button();
    }
    
    @Test
    public void testC_SearchEndEntities() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.fillSearchCriteria(END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
    }
    
    @Test
    public void testD_RevokeTestUser(){
        searchEndEntitiesHelper.chooseFromRevocationReason("Certificate hold");
        searchEndEntitiesHelper.triggerSearchResultFirstRowSelect();
        searchEndEntitiesHelper.clickRevokeSelected();
        acceptAlert();
    }
    
    @Test
    public void testE_ReactivateCertificate() {
        searchEndEntitiesHelper.clickViewCertificateForRow(END_ENTITY_COMMON_NAME);
        String mainWindow = webDriver.getWindowHandle();
        switchToCertificateViewPopup();
        searchEndEntitiesHelper.clickReactive();
        acceptAlert();
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    @Test
    public void testF_CheckReactiveBtnIsAvailible() {
        searchEndEntitiesHelper.clickViewCertificateForRow(END_ENTITY_COMMON_NAME);
        String mainWindow = webDriver.getWindowHandle();
        switchToCertificateViewPopup();
        List<WebElement> elements = webDriver.findElements(REACTIVE_BTN_XPATH); 
        Assert.assertFalse(elements.size() > 0);
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    @Test
    public void testG_AuditLogEndEntityAddedInDetails() {
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        WebElement addedElement = webDriver.findElement(AUDITLOG_DETAILS_ADDED_XPATH);
        auditLogHelper.assertLogEntryByEventText("End Entity Add", "Success", null,
                Collections.singletonList(addedElement.getText()));
    }
    
    @Test
    public void testH_AuditLogEndEntityRevokeInDetails() {
        WebElement revokedElement = webDriver.findElement(AUDITLOG_DETAILS_REVOKED_XPATH);
        auditLogHelper.assertLogEntryByEventText("End Entity Revoke", "Success", null,
                Collections.singletonList(revokedElement.getText()));
    }
    
    @Test
    public void testI_AuditLogEndEntityCertHoldInDetails() {
        WebElement certificateHoldElement = webDriver.findElement(AUDITLOG_DETAILS_CERTIFICATEHOLD_XPATH);
        auditLogHelper.assertLogEntryByEventText("Certificate Revoke", "Success", null,
                Collections.singletonList(certificateHoldElement.getText()));
    }
    
    @Test
    public void testJ_AuditLogEndEntityRevokeCertInDetails() {
        // Only checking 'Event' log by username.
        auditLogHelper.setViewFilteringCondition("Username", "Equals", END_ENTITY_NAME);
        auditLogHelper.assertLogEntryByEventText("Certificate Revoke", "Success", null,null);
    }
    
    private static void cleanup() {
        removeEndEntityByUsername(END_ENTITY_NAME);
        removeCertificateProfileByName(CERTIFICATE_PROFILE_NAME);
    }
    
    private static void switchToCertificateViewPopup() {
        for (String windowHandle : webDriver.getWindowHandles()) {
            webDriver.switchTo().window(windowHandle);
        }
    }
    
    private static void acceptAlert() {
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
    }
}
