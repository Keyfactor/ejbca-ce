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


import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper;
import org.ejbca.webtest.helper.SystemConfigurationHelper.SysConfigTabs;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test uses "send notifications" and requires that e-mail is configured in the appserver at java:/EjbcaMail .
 * You don't need an actual e-mail server, though. You can point it to some non-existent hostname.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa59_EEPHidden extends WebTestBase {
    
    private static class TestData {
        private static final Map<String,String> ASSERTION_FIELDMAP = new HashMap<>();
        private static final Map<String,String> INPUT_END_ENTITY_FIELDMAP = new HashMap<>();
        
        private static final String EEP_NAME = "Hidden";
        private static final String END_ENTITY_NAME = "TestEndEnityHidden";
        private static final String END_ENTITY_PASSWORD = "foo123";
        private static final String EMAIL_NAME = "sender";
        private static final String EMAIL_DOMAIN = "example.com";
        private static final int NOTIFICATION_INDEX = 0;

        // Map holding input fields and corresponding values
        static {
            INPUT_END_ENTITY_FIELDMAP.put("Username", END_ENTITY_NAME);
            INPUT_END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", END_ENTITY_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("Confirm Password", END_ENTITY_PASSWORD);
            INPUT_END_ENTITY_FIELDMAP.put("CN, Common name", END_ENTITY_NAME);
        }
        // Map holding input fields used for asserting existence
        static {
            ASSERTION_FIELDMAP.put("Username", null);
            ASSERTION_FIELDMAP.put("Password (or Enrollment Code)", null);
            ASSERTION_FIELDMAP.put("Confirm Password", null);
            ASSERTION_FIELDMAP.put("E-mail address", null);
            ASSERTION_FIELDMAP.put("CN, Common name", null);
        }
    }
    
    private static String currentDateString;
    private static String oneMonthsFromNowString;
    private static WebDriver webDriver;
    
    // Helpers
    private static SystemConfigurationHelper sysConfigHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    
    @BeforeClass
    public static void init() {
        Date currentDate = new Date();
        Calendar oneMonthsFromNow = Calendar.getInstance();
        oneMonthsFromNow.setTime(currentDate);
        oneMonthsFromNow.add(Calendar.MONTH, 1);
        currentDateString = new SimpleDateFormat("yyyy-MM-dd").format(currentDate);
        oneMonthsFromNowString = new SimpleDateFormat("yyyy-MM-dd").format(oneMonthsFromNow.getTime());
        beforeClass(true, null);
        webDriver = getWebDriver();
        sysConfigHelper = new SystemConfigurationHelper(webDriver);
        eeProfileHelper = new EndEntityProfileHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeEndEntityProfileByName(TestData.EEP_NAME);
        afterClass();
    }

    /** Attempts to enable key recovery through system configuration in the Admin Web. */
    @Test
    public void testA_enableKeyRecovery() {
        sysConfigHelper.openPage(getAdminWebUrl());
        sysConfigHelper.openTab(SysConfigTabs.BASICCONFIG);
        sysConfigHelper.triggerEnableKeyRecovery(true);
        sysConfigHelper.saveBasicConfiguration();
        sysConfigHelper.assertEnableKeyRecoveryEnabled(true);
    }

    @Test
    public void testB_addEndEntityProfile() {
        eeProfileHelper.openPage(getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.EEP_NAME);
        eeProfileHelper.openEditEndEntityProfilePage(TestData.EEP_NAME);
        // Set all desired values in EEP. Set values will be validated in next step (add end entity)
        eeProfileHelper.selectDefaultCa(getCaName());
        eeProfileHelper.triggerMaximumNumberOfFailedLoginAttempts();
        eeProfileHelper.triggerCertificateValidityStartTime();
        eeProfileHelper.triggerCertificateValidityEndTime();
        eeProfileHelper.setCertificateValidityStartTime(currentDateString);
        eeProfileHelper.setCertificateValidityEndTime(oneMonthsFromNowString);
        eeProfileHelper.triggerNameConstraints();
        eeProfileHelper.triggerExtensionData();
        eeProfileHelper.triggerNumberOfAllowedRequests();
        eeProfileHelper.triggerKeyRecoverable();
        eeProfileHelper.triggerIssuanceRevocationReason();
        eeProfileHelper.triggerSendNotification();
        eeProfileHelper.addNotification();
        eeProfileHelper.setNotificationSender(TestData.NOTIFICATION_INDEX, "sender@example.com");
        eeProfileHelper.setNotificationSubject(TestData.NOTIFICATION_INDEX,"test subject");
        eeProfileHelper.setNotificationMessage(TestData.NOTIFICATION_INDEX, "test message");
        // Save configuration
        eeProfileHelper.saveEndEntityProfile(true);

        // Assert that the EEP exists
        eeProfileHelper.assertEndEntityProfileNameExists(TestData.EEP_NAME);
    }

    @Test
    public void testC_checkEep() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        
        addEndEntityHelper.setEndEntityProfile(TestData.EEP_NAME);
        addEndEntityHelper.assertEndEntityProfileSelected(TestData.EEP_NAME);
        addEndEntityHelper.assertCertificateProfileSelected("ENDUSER");
        addEndEntityHelper.assertTokenSelected("User Generated");
        addEndEntityHelper.assertNumberOfAllowedRequestsSelected("1");
        addEndEntityHelper.assertRevocationReasonSelected("Active");
        addEndEntityHelper.assertKeyRecoveryEnabled(false);
        addEndEntityHelper.assertFieldsExists(TestData.ASSERTION_FIELDMAP);
        addEndEntityHelper.assertFieldNameConstraintsPermittedExists();
    }

    @Test
    public void testD_addEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());

        addEndEntityHelper.setEndEntityProfile(TestData.EEP_NAME);
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.fillFields(TestData.INPUT_END_ENTITY_FIELDMAP);
        addEndEntityHelper.fillFieldEmail(TestData.EMAIL_NAME, TestData.EMAIL_DOMAIN);
        addEndEntityHelper.fillFieldNameConstraintsPermitted(
                "example.com\n" +
                "198.51.100.0/24\n" +
                "CN=Name,O=Company @example.com"
                );
        addEndEntityHelper.fillFieldExtensionData("Other Data");
        addEndEntityHelper.triggerSendNotifications();
        addEndEntityHelper.addEndEntity();
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME);
    }
}
