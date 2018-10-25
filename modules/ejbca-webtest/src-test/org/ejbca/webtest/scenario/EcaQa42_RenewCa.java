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

import static org.junit.Assert.assertEquals;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

/**
 * CAs can be renewed in different ways, only the CA certificate can be renewed
 * using the same keys or both the CA keys and the certificate can be renewed.
 * In this test case both scenarios are tested.
 * 
 * @version $Id: EcaQa42_RenewCa.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa42_RenewCa extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static AuditLogHelper auditLogHelper;
    // Test Data
    private static class TestData {
        static final String CA_NAME = "ECAQA-42-TestCA";
        static final String TEXT_CA_RENEWAL_ALERT_MESSAGE = "Are you sure you want to renew this CA?";
        static final String TEXT_CA_RENEWAL_SUCCESS_MESSAGE = "CA Renewed Successfully";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.CA_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_addCa() {
        caHelper.openPage(getAdminWebUrl());
        CaHelper.add(webDriver, TestData.CA_NAME);
        CaHelper.setValidity(webDriver, "1y");
        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, TestData.CA_NAME);
    }

    @Test
    public void stepB_renewWithOldKeys() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        CaHelper.edit(webDriver, TestData.CA_NAME);
        assertEquals("", "signKey", new Select(webDriver.findElement(By.xpath("//select[@name='selectcertsignkeyrenew']"))).getFirstSelectedOption().getText());
        caHelper.renewCaAndAssert(TestData.TEXT_CA_RENEWAL_ALERT_MESSAGE, true, TestData.TEXT_CA_RENEWAL_SUCCESS_MESSAGE, TestData.CA_NAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText("CA Renewal", "Success", TestData.CA_NAME, null);
    }

    @Test
    public void stepC_renewWithNewKeys() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        CaHelper.edit(webDriver, TestData.CA_NAME);
        new Select(webDriver.findElement(By.xpath("//select[@name='selectcertsignkeyrenew']"))).selectByVisibleText("– Generate new key using KeySequence –");
        caHelper.renewCaAndAssert(TestData.TEXT_CA_RENEWAL_ALERT_MESSAGE, true, TestData.TEXT_CA_RENEWAL_SUCCESS_MESSAGE, TestData.CA_NAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText("CA Renewal", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("Crypto Token Key Pair Generate", "Success", null, null);
    }

    @Test
    public void stepD_checkNewKeys() {
        caHelper.openPage(getAdminWebUrl());
        CaHelper.edit(webDriver, TestData.CA_NAME);
        assertEquals("Unexpected value for certSignKey", "signKey00001", webDriver.findElement(By.xpath("//td[text()='certSignKey']//following-sibling::td")).getText());
        assertEquals("Unexpected value for crlSignKey", "signKey00001", webDriver.findElement(By.xpath("//td[text()='crlSignKey']//following-sibling::td")).getText());
        assertEquals("Unexpected value for Key sequence", "00001", webDriver.findElement(By.xpath("//input[@name='textfieldkeysequence']")).getAttribute("value"));
    }

}
