package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CTLogHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openqa.selenium.WebDriver;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class EcaQa152_OrderOfCTLogs extends WebTestBase {

    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFJY5TplekPjaNgCckezeyhkccA8O\n" +
            "63Sj84rZ1RCRoJ7vHa8FF2IIbF/S1iEb/gbkmqNJ4K3m+oNzcr76yoH3Dg==\n" +
            "-----END PUBLIC KEY-----";

    private static final String UNLABELED = "Unlabeled";

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

    @Test
    public void stepA_addCertificateTransparencyLog() throws IOException {
        final String logUrl = "https://localhost:8443/ejbca/adminweb/ct/v1";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(60000);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl);
    }

    @Test
    public void stepB_addCertificateTransparencyLog() throws Exception {
        final String logUrl = "https://localhost:8443/ejbca/doc/adminguide.html#Certificate%20Transparency%20%28Enterprise%20only%29";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(30000);
        ctLogHelper.fillLabelField(UNLABELED);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(UNLABELED, logUrl);
    }

    @Test
    public void stepC_addCertificateTransparencyLog() throws Exception {
        final String logUrl = "https://localhost:8443/ejbca";
        final String label = "Test_EJBCA";

        goToSystemConfigurationPage();

        ctLogHelper.fillLogUrlField(logUrl);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(30000);
        ctLogHelper.fillLabelField(label);
        ctLogHelper.addCertificateTransparencyLog();

        ctLogHelper.assertIsTableAndRowExists(label, logUrl);
    }

    @Test
    public void stepD_reloadCertificateTransparencyLogs(){
        goToSystemConfigurationPage();
        ctLogHelper.assertIsTableRowsCorrectOrder();
    }

    @Test
    public void stepE_pressArrowsToChangeTheOrderOfTheCertificateTransparencyAuditLogs(){

    }

    @Test
    public void stepF_moveTheLogToTheBottomOfALogGroup(){

    }

    @Test
    public void stepF_moveTheLogToTheTopOfALogGroup(){

    }

    private void goToSystemConfigurationPage(){
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
