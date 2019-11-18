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
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigTabs;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

/**
 * 
 * @version $Id$
 *
 */
public class EcaQa155_EditCTLogLogURLMandatoryCheckboxAndTimeout extends WebTestBase {
    
    private static SystemConfigurationHelper systemConfigurationHelper;
    private static String LOG_URL = "https://localhost:8443/ejbca/adminweb/";
    
    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();

        // Init helpers
        systemConfigurationHelper = new SystemConfigurationHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // super
        afterClass();
    }
    
    @Test
    public void stepOne_CtLogPageOpen(){
        systemConfigurationHelper.openPage(getAdminWebUrl());
        systemConfigurationHelper.openTab(SysConfigTabs.CTLOGS);
    }
    
    @Test
    public void stepTwo_CtLogAddFirstLog() {
        
    }
    
    @Test
    public void stepThree_CtLogEditFirstLog() {
        
    }
    
    @Test
    public void stepFour_CtLogAddSecondLog() {
        
    }
    
    
}
