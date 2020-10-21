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

import java.io.IOException;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CTLogHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Test objective is to check the order of CT logs when saving system configuration, it's possible that the order does
 * not change by luck, so there is a need to try it several times, with different URLs.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-152">ECAQA-152</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa152_OrderOfCTLogs extends WebTestBase {

    private static final String UNLABELED = "Unlabeled";
    private static final String LOG_URL_A = "/adminweb/ct/v1/";
    private static final String LOG_URL_B = "/doc/adminguide.html#Certificate%20Transparency%20%28Enterprise%20only%29/ct/v1/";
    private static final String LOG_URL_C =  "/ct/v1/";
    private static final String TIMEOUT_ONE = "60000";
    private static final String TIMEOUT_TWO = "30000";

    private static CTLogHelper ctLogHelper;
    private static SystemConfigurationHelper sysConfigHelper;
    
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        ctLogHelper = new CTLogHelper(webDriver);
        sysConfigHelper = new SystemConfigurationHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeCertificateTransparencyLogs(getBaseUrl() + LOG_URL_A, getBaseUrl() + LOG_URL_B,getBaseUrl() +  LOG_URL_C);
        afterClass();
    }

    @Test
    public void stepA_addCertificateTransparencyLog() throws IOException {
        final String logUrl = getBaseUrl() + "/adminweb/ct/v1";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(ctLogHelper.createPublicKeyFile(folder));
        ctLogHelper.fillTimeoutField(TIMEOUT_ONE);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl, TIMEOUT_ONE);
    }

    @Test
    public void stepB_addCertificateTransparencyLog() throws Exception {
        final String logUrl = getBaseUrl() + "/doc/adminguide.html#Certificate%20Transparency%20%28Enterprise%20only%29";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(ctLogHelper.createPublicKeyFile(folder));
        ctLogHelper.fillTimeoutField(TIMEOUT_TWO);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl, TIMEOUT_TWO);
    }

    @Test
    public void stepC_addCertificateTransparencyLog() throws Exception {
        final String logUrl = getBaseUrl();
        final String label = "Test_EJBCA";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(ctLogHelper.createPublicKeyFile(folder));
        ctLogHelper.fillTimeoutField(TIMEOUT_TWO);
        ctLogHelper.fillLabelField(label);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(label, logUrl, TIMEOUT_TWO);
    }

    @Test
    public void stepD_reloadCertificateTransparencyLogs() {
        goToSystemConfigurationPage();
        ctLogHelper.assertIsTableRowsCorrectOrder(0, getBaseUrl() +LOG_URL_C);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, getBaseUrl() + LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, getBaseUrl() + LOG_URL_B);
    }

    @Test
    public void stepE_pressArrowsToChangeTheOrderOfTheCertificateTransparencyAuditLogs() {
        goToSystemConfigurationPage();
        String fullLogUrlA = getBaseUrl() + LOG_URL_A;
        ctLogHelper.pressArrowDownButton(UNLABELED, fullLogUrlA);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, getBaseUrl() + LOG_URL_B);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, fullLogUrlA);
        ctLogHelper.pressArrowUpButton(UNLABELED, fullLogUrlA);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, fullLogUrlA);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, getBaseUrl() + LOG_URL_B);
    }

    @Test
    public void stepF_moveTheLogToTheBottomOfALogGroup() {
        String fullLogUrlA = getBaseUrl() + LOG_URL_A;
        ctLogHelper.pressArrowDownButton(UNLABELED, fullLogUrlA);

        ctLogHelper.assertIsTableRowsCorrectOrder(1, getBaseUrl() + LOG_URL_B);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, fullLogUrlA);
        ctLogHelper.isArrowDownButtonDisabled(UNLABELED, fullLogUrlA);
    }

    @Test
    public void stepG_moveTheLogToTheTopOfALogGroup() {
        String fullLogUrlA = getBaseUrl() + LOG_URL_A;
        ctLogHelper.pressArrowUpButton(UNLABELED, fullLogUrlA);

        ctLogHelper.assertIsTableRowsCorrectOrder(1, fullLogUrlA);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, getBaseUrl() +LOG_URL_B);
        ctLogHelper.isArrowUpButtonDisabled(UNLABELED, fullLogUrlA);
    }

    private void goToSystemConfigurationPage() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SystemConfigurationHelper.SysConfigTabs.CTLOGS);
    }
}
