package org.ejbca.webtest.scenario;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CTLogHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa152_OrderOfCTLogs extends WebTestBase {

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFJY5TplekPjaNgCckezeyhkccA8O\n" +
            "63Sj84rZ1RCRoJ7vHa8FF2IIbF/S1iEb/gbkmqNJ4K3m+oNzcr76yoH3Dg==\n" +
            "-----END PUBLIC KEY-----";

    private static final String UNLABELED = "Unlabeled";
    private static final String LOG_URL_A = "https://localhost:8443/ejbca/adminweb/ct/v1/";
    private static final String LOG_URL_B = "https://localhost:8443/ejbca/doc/adminguide.html#Certificate%20Transparency%20%28Enterprise%20only%29/ct/v1/";
    private static final String LOG_URL_C = "https://localhost:8443/ejbca/ct/v1/";
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
    public static void exit() throws AuthorizationDeniedException {
        removeCertificateTransparencyLogs(LOG_URL_A, LOG_URL_B, LOG_URL_C);
        afterClass();
    }

    @Test
    public void stepA_addCertificateTransparencyLog() throws IOException {
        final String logUrl = "https://localhost:8443/ejbca/adminweb/ct/v1";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(TIMEOUT_ONE);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl, TIMEOUT_ONE);
    }

    @Test
    public void stepB_addCertificateTransparencyLog() throws Exception {
        final String logUrl = "https://localhost:8443/ejbca/doc/adminguide.html#Certificate%20Transparency%20%28Enterprise%20only%29";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(TIMEOUT_TWO);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl, TIMEOUT_TWO);
    }

    @Test
    public void stepC_addCertificateTransparencyLog() throws Exception {
        final String logUrl = "https://localhost:8443/ejbca";
        final String label = "Test_EJBCA";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(TIMEOUT_TWO);
        ctLogHelper.fillLabelField(label);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(label, logUrl, TIMEOUT_TWO);
    }

    @Test
    public void stepD_reloadCertificateTransparencyLogs() {
        goToSystemConfigurationPage();
        ctLogHelper.assertIsTableRowsCorrectOrder(0, LOG_URL_C);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, LOG_URL_B);
    }

    @Test
    public void stepE_pressArrowsToChangeTheOrderOfTheCertificateTransparencyAuditLogs() {
        goToSystemConfigurationPage();
        ctLogHelper.pressArrowDownButton(UNLABELED, LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, LOG_URL_B);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, LOG_URL_A);
        ctLogHelper.pressArrowUpButton(UNLABELED, LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(1, LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, LOG_URL_B);
    }

    @Test
    public void stepF_moveTheLogToTheBottomOfALogGroup() {
        ctLogHelper.pressArrowDownButton(UNLABELED, LOG_URL_A);

        ctLogHelper.assertIsTableRowsCorrectOrder(1, LOG_URL_B);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, LOG_URL_A);
        ctLogHelper.isArrowDownButtonDisabled(UNLABELED, LOG_URL_A);
    }

    @Test
    public void stepG_moveTheLogToTheTopOfALogGroup() {
        ctLogHelper.pressArrowUpButton(UNLABELED, LOG_URL_A);

        ctLogHelper.assertIsTableRowsCorrectOrder(1, LOG_URL_A);
        ctLogHelper.assertIsTableRowsCorrectOrder(2, LOG_URL_B);
        ctLogHelper.isArrowUpButtonDisabled(UNLABELED, LOG_URL_A);
    }

    private void goToSystemConfigurationPage() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SystemConfigurationHelper.SysConfigTabs.CTLOGS);
    }

    private File createPublicKeyFile() throws IOException {
        File publicKeyFile = folder.newFile("test_pub.pem");
        FileWriter fileWriter = new FileWriter(publicKeyFile);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        bufferedWriter.write(PUBLIC_KEY);
        bufferedWriter.close();
        return publicKeyFile;
    }
}
