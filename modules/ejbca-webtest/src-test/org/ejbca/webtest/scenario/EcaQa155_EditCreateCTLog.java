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
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.openqa.selenium.WebDriver;

/**
 * CT Log timeout editable again, as well as the other fields.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-155">ECAQA-155</a>
 *
 * @version $Id$
 */
public class EcaQa155_EditCreateCTLog extends WebTestBase {
    
    private static final String INIT_LABEL = "Test";
    private static final String EDIT_LABEL = "ECAQA-155";
    private static final String INIT_LOG_URL = "https://localhost:8443/ejbca/adminweb/";
    private static final String EDIT_LOG_URL = "https://localhost:8443/ejbca/ct/v1/";
    private static final String INITIAL_TIMEOUT = "60000";
    private static final String EDITED_TIMEOUT = "120000";
    
    private static SystemConfigurationHelper systemConfigurationHelper;
    private static CTLogHelper ctLogHelper;
    
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
    public static void exit() {
        removeCertificateTransparencyLogs(INIT_LOG_URL,EDIT_LOG_URL);
        // super
        afterClass();
    }
    
    @Test
    public void stepTwo_CtLogEditFirstLog() throws IOException {
        goToSystemConfigurationPage();
        ctLogHelper.fillLogUrlField(INIT_LOG_URL);
        ctLogHelper.fillPublicKeyField(ctLogHelper.createPublicKeyFile(folder));
        ctLogHelper.fillTimeoutField(INITIAL_TIMEOUT);
        ctLogHelper.fillLabelField(INIT_LABEL);
        ctLogHelper.addCertificateTransparencyLog();
        ctLogHelper.assertIsTableAndRowExists(INIT_LABEL, INIT_LOG_URL, INITIAL_TIMEOUT);
        
        ctLogHelper.pressEditCtLogButton(INIT_LABEL, INIT_LOG_URL);
        ctLogHelper.fillEditLogUrlField(EDIT_LOG_URL);
        ctLogHelper.fillEditTimeoutField(EDITED_TIMEOUT);
        ctLogHelper.fillEditLabelField(EDIT_LABEL);
        ctLogHelper.pressSaveEditCtLogButton();
        ctLogHelper.assertIsTableAndRowExists(EDIT_LABEL, EDIT_LOG_URL, EDITED_TIMEOUT);
    }
    
    private void goToSystemConfigurationPage(){
        systemConfigurationHelper.openPage(getAdminWebUrl());
        systemConfigurationHelper.openTab(SystemConfigurationHelper.SysConfigTabs.CTLOGS);
    }

}
