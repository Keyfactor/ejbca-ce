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
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CaStructureHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Selenium test that tests CRL Issuance
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-220">ECAQA-220</a>
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa220_CRLIssuance extends WebTestBase {

    private static AuditLogHelper auditLogHelper;
    private static CaHelper caHelper;
    private static CaStructureHelper caStructureHelper;

    private static class TestData {
        private static final String CA_NAME = "ECAQA-220-TestCA";
        private static final String CA_VALIDITY = "1y";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        auditLogHelper = new AuditLogHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        caStructureHelper = new CaStructureHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeCaAndCryptoToken(TestData.CA_NAME);
        removeCrlByIssuerDn("CN=" + TestData.CA_NAME);
        afterClass();
    }

    @Test
    public void stepA_AddCA() {
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }
    
    @Test
    public void stepB_CheckAuditLog() {
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertLogEntryByEventText("CRL Store", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("CRL Create", "Success", TestData.CA_NAME, null);
    }

    @Test
    public void stepC_CreateCRL() {
        auditLogHelper.initFilterTime();
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.assertCrlLinkWorks(TestData.CA_NAME);
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(TestData.CA_NAME);
    }
    
    @Test
    public void stepD_CheckAuditLog() {
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertLogEntryByEventText("CRL Store", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("CRL Create", "Success", TestData.CA_NAME, null);
    }
}
