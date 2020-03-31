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

import java.util.HashMap;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;



@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa219_RevokeEndEntityCertificate extends WebTestBase {
    //Classes used.
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    private static CaHelper caHelper;
    private static RaWebHelper raWebHelper;
    
    //String variables.
    private static final String END_ENTITY_NAME = "ECAQA71EE";
    private static final String END_ENTITY_PASSWORD = "foo123";
    private static final String END_ENTITY_COMMON_NAME = "ECAQA71EE";
    private static final String CA_NAME = "ECAQA71CA";
    private static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
    private static final String CA_VALIDITY = "15y";
    private static final By REVOKE_SELECTED_BUTTON_XPATH = By.xpath("//input[@name='buttonrevokeusers']");
    private static final By CERTIFICATE_SERIAL_NUMBER_XPATH = By.xpath("//*[@id='contentBlock']//label[contains(text(),'Certificate Serial Number')]/../following-sibling::td/label");

    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(END_ENTITY_NAME);
        removeCertificateProfileByName(CERTIFICATE_PROFILE_NAME);
        removeCaByName(CA_NAME);
        removeCryptoTokenByCaName(CA_NAME);
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        caHelper = new CaHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        cleanup();
        afterClass();
    }
    
    
    @Test
    public void testA_addCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(CA_NAME);
        // Set validity (required)
        caHelper.setValidity(CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(CA_NAME);
    }

    @Test
    public void testB_AddEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", END_ENTITY_PASSWORD);
        fields.put("Confirm Password", END_ENTITY_PASSWORD);
        fields.put("CN, Common name", END_ENTITY_COMMON_NAME);
        addEndEntityHelper.setToken("P12 file");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.addEndEntity();
    }

    @Test
    public void testC_RaWebSaveP12() {
        raWebHelper.openPage(getRaWebUrl());
        //Use sleep to find element.
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        raWebHelper.clickToEnrollUseUsernamen(webDriver);
        raWebHelper.fillEnrollUsernameAndCode(END_ENTITY_NAME, END_ENTITY_PASSWORD);
        raWebHelper.clickCheck();
        raWebHelper.clickEnrollDownloadPKCS12Button();
    }

    @Test
    public void testD_SearchEndEntities() {
        String mainWindow = webDriver.getWindowHandle();
        getStringFromSearchEndEntities();
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    private String getStringFromSearchEndEntities() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.fillSearchCriteria(END_ENTITY_NAME, null, "All", null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.triggerSearchResultUsernameRowSelect(END_ENTITY_COMMON_NAME);
        WebElement revokeButton = webDriver.findElement(REVOKE_SELECTED_BUTTON_XPATH);
        revokeButton.click();

        //Handles the CertificateView Popup-window.
        acceptAlert();
        searchEndEntitiesHelper.clickViewCertificateForRow(END_ENTITY_COMMON_NAME);
        for (String windowHandle : webDriver.getWindowHandles()) {
            webDriver.switchTo().window(windowHandle);
        }
        WebElement certificateSerialNumberElement = webDriver.findElement(CERTIFICATE_SERIAL_NUMBER_XPATH);
        return certificateSerialNumberElement.getText();
    }
    
    private static void acceptAlert() {
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
    }    
}
