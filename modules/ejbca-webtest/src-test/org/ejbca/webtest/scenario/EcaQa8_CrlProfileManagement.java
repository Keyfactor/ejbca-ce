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

import java.util.Arrays;

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
 * CRL profiles don't exist as independent entities, but are instead an inherent
 * part of CAs. Thus there are no dedicated CRL profile Audit Log statements,
 * instead modifying the CRL profile values within a CA will be logged under the
 * standard log statements for modifying CAs.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-8">ECAQA-8</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa8_CrlProfileManagement extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static AuditLogHelper auditLogHelper;
    // Test Data
    private static class TestData {
        private static final String CA_NAME = "ECAQA-8-TestCA";
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
        // Update default timestamp
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");

        // CRL settings
        caHelper.setCrlPeriod("1d");
        caHelper.setCrlIssueInterval("22h");
        caHelper.setCrlOverlapTime("30m");

        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);

        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText("CRL Create", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("CRL Store", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("Certificate Store", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("CA Edit", "Success", TestData.CA_NAME, null);
        auditLogHelper.assertLogEntryByEventText("CA Create", "Success", TestData.CA_NAME, null);
    }

    @Test
    public void stepB_editCa() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);

        // Change 'CRL Issue Interval'
        caHelper.setCrlIssueInterval("20h");

        caHelper.saveCa();
        caHelper.assertExists(TestData.CA_NAME);

        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "CA Edit",
                "Success",
                TestData.CA_NAME,
                Arrays.asList(
                        "msg=CA with id",
                        "and name " + TestData.CA_NAME + " edited",
                        "changed:crlIssueInterval=72000000"
                )
        );
    }
}
