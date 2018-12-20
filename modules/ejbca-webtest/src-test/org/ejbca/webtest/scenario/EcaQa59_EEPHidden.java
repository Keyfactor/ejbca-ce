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

import static org.junit.Assert.assertEquals;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
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
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa59_EEPHidden extends WebTestBase {
    
    private static class TestData {
        private static final Map<String,String> ASSERTION_FIELDMAP = new HashMap<String, String>();
        private static final Map<String,String> INPUT_END_ENTITY_FIELDMAP = new HashMap<String, String>();
        
        private static final String EEP_NAME = "Hidden";
        private static final String END_ENTITY_NAME = "TestEndEnityHidden";
        private static final String END_ENTITY_PASSWORD = "foo123";
        private static final String EMAIL_NAME = "sender";
        private static final String EMAIL_DOMAIN = "example.com";
        
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
    public static void exit() throws NoSuchEndEntityException, AuthorizationDeniedException, CouldNotRemoveEndEntityException {
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeEndEntityProfileByName(TestData.EEP_NAME);
        webDriver.quit();
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
        Select dropDownCa =  new Select(webDriver.findElement(By.xpath("//select[@name='selectdefaultca']")));
        dropDownCa.selectByVisibleText(getCaName());
        webDriver.findElement(By.id("checkboxusemaxfailedlogins")).click();
        webDriver.findElement(By.id("checkboxsusetarttime")).click();
        webDriver.findElement(By.id("checkboxuseendtime")).click();
        webDriver.findElement(By.xpath("//input[@name='textfieldstarttime']")).sendKeys(currentDateString);
        webDriver.findElement(By.xpath("//input[@name='textfieldendtime']")).sendKeys(oneMonthsFromNowString);
        webDriver.findElement(By.id("checkboxusencpermitted")).click();
        webDriver.findElement(By.id("checkboxuseextensiondata")).click();
        webDriver.findElement(By.id("checkboxuseallowedrequests")).click();
        webDriver.findElement(By.id("checkboxusekeyrecoverable")).click();
        webDriver.findElement(By.id("checkboxuseissuancerevocationreason")).click();
        webDriver.findElement(By.id("checkboxusesendnotification")).click();
        webDriver.findElement(By.xpath("//input[@name='buttonaddnotification']")).click();
        webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsender']")).sendKeys("sender@example.com");
        webDriver.findElement(By.xpath("//input[@name='textfieldnotificationsubject']")).sendKeys("test subject");
        webDriver.findElement(By.xpath("//textarea[@name='textareanotificationmessage']")).sendKeys("test message");
        // Save configuration
        webDriver.findElement(By.xpath("//input[@name='buttonsave']")).click();
        WebElement tableResult = webDriver.findElement(By.xpath("//table[@class='list']/tbody/tr/td"));
        assertEquals("Status text 'End Entity Profile saved' could not be found after saving EEP", "End Entity Profile saved.", tableResult.getText());
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

    // TODO If EjbcaMail isn't available in appserver this test errors. Should fail test immediately in that case
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
