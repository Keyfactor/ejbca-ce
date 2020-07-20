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
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigProtokols;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigTabs;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test verifies that enabling ACME works.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-187">ECAQA-187</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa187_EnableACME extends WebTestBase {
    
    private static WebDriver webDriver;
    private static AuditLogHelper auditLogHelper;
    private static SystemConfigurationHelper systemConfigurationHelper;
    
    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        systemConfigurationHelper = new SystemConfigurationHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
        auditLogHelper.initFilterTime();
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    /**
     * Enables ACME. Will do nothing if ACME is already enabled.
     */
    @Test
    public void stepA_EnableAcmeFirstTime() {
        systemConfigurationHelper.openPage(getAdminWebUrl());
        systemConfigurationHelper.openTab(SysConfigTabs.PROTOCOLCONFIG);
        systemConfigurationHelper.enableProtocol(SysConfigProtokols.ACME);
        systemConfigurationHelper.assertProtocolEnabled(SysConfigProtokols.ACME);
    }
    
    /**
     * Disables ACME so it can be enabled (again) in the next step.
     */
    @Test
    public void stepB_DisableAcme() {
        systemConfigurationHelper.disableProtocol(SysConfigProtokols.ACME);
        systemConfigurationHelper.assertProtocolDisabled(SysConfigProtokols.ACME);
    }
    
    /**
     * Enables ACME the second time since if there is no configuration to begin with the first enabling won't generate a configuration edit event in the audit log.
     */
    @Test
    public void stepC_EnableAcmeSecondTime() {
        systemConfigurationHelper.enableProtocol(SysConfigProtokols.ACME);
        systemConfigurationHelper.assertProtocolEnabled(SysConfigProtokols.ACME);
    }

    @Test
    public void stepD_CheckAuditLog() {
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.reloadView();
        auditLogHelper.assertProtocolEnabledLogExists("ACME");
    }
}