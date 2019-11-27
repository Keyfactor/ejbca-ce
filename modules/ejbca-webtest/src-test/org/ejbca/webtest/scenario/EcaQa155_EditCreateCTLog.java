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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CTLogHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openqa.selenium.WebDriver;

/**
 * 
 * @version $Id$
 *
 */
public class EcaQa155_EditCreateCTLog extends WebTestBase {
    
    private static final String INIT_LABEL = "Test";
    private static final String EDIT_LABEL = "ECAQA-155";
    private static final String INIT_LOG_URL = "https://localhost:8443/ejbca/adminweb/";
    private static final String EDIT_LOG_URL = "https://localhost:8443/ejbca/ct/v1/";
    private static final int INITIAL_TIMEOUT = 60000;
    private static final String EDITED_TIMEOUT = "120000";
    
    private static SystemConfigurationHelper systemConfigurationHelper;
    private static CTLogHelper ctLogHelper;
    
    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFJY5TplekPjaNgCckezeyhkccA8O\n" +
            "63Sj84rZ1RCRoJ7vHa8FF2IIbF/S1iEb/gbkmqNJ4K3m+oNzcr76yoH3Dg==\n" +
            "-----END PUBLIC KEY-----";
    
    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    
    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();

        // Init helpers
        systemConfigurationHelper = new SystemConfigurationHelper(webDriver);
        ctLogHelper = new CTLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        removeCertificateTransparencyLogs(INIT_LOG_URL,EDIT_LOG_URL);
        // super
        afterClass();
    }
    
    @Test
    public void stepTwo_CtLogEditFirstLog() throws IOException, AuthorizationDeniedException {
        goToSystemConfigurationPage();
        ctLogHelper.fillLogUrlField(INIT_LOG_URL);
        ctLogHelper.fillPublicKeyField(createPublicKeyFile());
        ctLogHelper.fillTimeoutField(INITIAL_TIMEOUT);
        ctLogHelper.fillLabelField(INIT_LABEL);
        ctLogHelper.addCertificateTransparencyLog();
        ctLogHelper.assertIsTableAndRowExists(INIT_LABEL, INIT_LOG_URL);
        ctLogHelper.pressEditCtLogButton(INIT_LABEL, INIT_LOG_URL);
        ctLogHelper.fillEditLogUrlField(EDIT_LOG_URL);
        ctLogHelper.fillEditTimeoutField(EDITED_TIMEOUT);
        ctLogHelper.fillEditLabelField(EDIT_LABEL);
        ctLogHelper.pressSaveEditCtLogButton();
        ctLogHelper.assertIsTableAndRowExists(EDIT_LABEL, EDIT_LOG_URL);
    }
    
    @Test
    public void stepThree_CtLogAddSecondLog() {
        
    }
    
    private void goToSystemConfigurationPage(){
        systemConfigurationHelper.openPage(getAdminWebUrl());
        systemConfigurationHelper.openTab(SystemConfigurationHelper.SysConfigTabs.CTLOGS);
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
