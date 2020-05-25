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

    // Helpers
    private static CaHelper caHelper;
    private static AuditLogHelper auditLogHelper;
    // Test Data
    private static class TestData {
        private static final String CA_NAME = "ECAQA-8-TestCA";
        private static final String CA_VALIDITY = "1y";
        private static final String CA_CRL_PERIOD = "1d";
        private static final String CA_CRL_ISSUEINTERVAL= "22h";
        private static final String CA_CRL_ISSUEINTERVAL_UPDATE= "20h";
        private static final String CA_CRL_OVERLAPTIME = "30m";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
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
        caHelper.setValidity(TestData.CA_VALIDITY);

        // CRL settings
        caHelper.setCrlPeriod(TestData.CA_CRL_PERIOD);
        caHelper.setCrlIssueInterval(TestData.CA_CRL_ISSUEINTERVAL);
        caHelper.setCrlOverlapTime(TestData.CA_CRL_OVERLAPTIME);

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
        caHelper.setCrlIssueInterval(TestData.CA_CRL_ISSUEINTERVAL_UPDATE);

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
