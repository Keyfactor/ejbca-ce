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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * CAs can be renewed in different ways, only the CA certificate can be renewed
 * using the same keys or both the CA keys and the certificate can be renewed.
 * In this test case both scenarios are tested.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa42_RenewCa extends WebTestBase {

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
        WebDriver webDriver = getWebDriver();
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
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepB_renewWithOldKeys() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertSelectCertsignKeyRenew("signKey");
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
        caHelper.edit(TestData.CA_NAME);
        caHelper.setNextCaKey("– Generate new key using KeySequence –");
        caHelper.renewCaAndAssert(TestData.TEXT_CA_RENEWAL_ALERT_MESSAGE, true, TestData.TEXT_CA_RENEWAL_SUCCESS_MESSAGE, TestData.CA_NAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText("CA Renewal", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("Crypto Token Key Pair Generate", "Success", null, null);
    }

    @Test
    public void stepD_checkNewKeys() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertCertSignKeyValue("signKey00001");
        caHelper.assertCrlSignKeyValue("signKey00001");
        caHelper.assertKeysequence("00001");
    }

}
