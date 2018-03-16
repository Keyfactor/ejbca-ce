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

package org.ejbca.webtest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.WebTestBase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

import static org.junit.Assert.*;

/**
 * Automated web test for ECAQA-138, which has the purpose of verifying that
 * an EEP with empty attributes that are non-modifiable cannot be saved.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa138_EEPAttributes extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
    private static final String eepName = "ECAQA138";

    private static WebDriver webDriver;
    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    // Strings for test
    private static final String saveSuccessfulMessage = "End Entity Profile saved.";
    private static final String alertMessage = "An empty attribute cannot be non-modifiable.";
    private static final String subjectDnBase = "subjectdn";
    private static final String subjectDnAttribute = "O, Organization";
    private static final String subjectDnString = "TestOrg";
    private static final String subjectAltNameBase = "subjectaltname";
    private static final String subjectAltNameAttribute = "MS UPN, User Principal Name";
    private static final String subjectAltNameString = "testdomain.com";
    private static final String subjectDirAttrBase = "subjectdirattr";
    private static final String subjectDirAttrAttribute = "Place of birth";
    private static final String subjectDirAttrString = "Stockholm";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        webDriver.quit();
    }

    @Test
    public void testA_addEEP() {
        // Open Manage End Entity Profiles page
        webDriver.get(getAdminWebUrl());
        webDriver.findElement(By.xpath("//a[contains(@href,'editendentityprofiles.jsp')]")).click();

        // Add EEP
        WebElement nameInput = webDriver.findElement(By.xpath("//input[@name='textfieldprofilename']"));
        nameInput.sendKeys(eepName);
        webDriver.findElement(By.xpath("//input[@name='buttonaddprofile']")).click();
    }

    @Test
    public void testB_subjectDn() {
        testAttribute(subjectDnBase, subjectDnAttribute, 1, subjectDnString);
    }

    @Test
    public void testC_subjectAltName() {
        testAttribute(subjectAltNameBase, subjectAltNameAttribute, 0, subjectAltNameString);
    }

    @Test
    public void testC_subjectDirAttr() {
        testAttribute(subjectDirAttrBase, subjectDirAttrAttribute, 0, subjectDirAttrString);
    }

    private void testAttribute(String attributeType, String attributeName, int attributeIndex, String testString) {
        // Edit EEP
        editEEP();

        // Add the Subject DN attribute
        addAttribute(attributeType, attributeName);

        // Save EEP
        saveEEP();

        // Check save successful
        saveSuccessful();

        // Edit EEP
        editEEP();

        // Uncheck Modifiable check-box
        triggerModifiable(attributeType, attributeIndex);

        // Save EEP
        saveEEP();

        // Assert that there was an alert with the correct message
        assertAlert();

        // Fill in the test string in the attribute field
        inputTestString(attributeType, attributeIndex, testString);

        // Save EEP
        saveEEP();

        // Check save successful
        saveSuccessful();
    }

    private void editEEP() {
        // Select EEP
        WebElement listTable = webDriver.findElement(By.xpath("//select[@name='selectprofile']"));
        WebElement listItem = listTable.findElement(By.xpath("//option[@value='" + eepName + "']"));
        assertEquals(eepName + " was not found in the list of End Entity Profiles", eepName, listItem.getText());
        listItem.click();

        // Click edit button
        webDriver.findElement(By.xpath("//input[@name='buttoneditprofile']")).click();

        // Assert correct EEP being edited
        WebElement currentProfile = webDriver.findElement(By.xpath("//input[@name='hiddenprofilename']"));
        assertEquals("The profile being edited was not " + eepName, eepName, currentProfile.getAttribute("value"));
    }

    private void saveEEP() {
        webDriver.findElement(By.xpath("//input[@name='buttonsave']")).click();
    }

    private void saveSuccessful() {
        Boolean saveSuccessful = webDriver.findElements(By.xpath("//td[contains(text(), '" + saveSuccessfulMessage + "')]")).size() == 1;
        assertTrue("The EEP was not saved successfully", saveSuccessful);
    }

    private void addAttribute(String attributeType, String attributeName) {
        // Select attribute in list
        Select attributeSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectadd" + attributeType + "']")));
        attributeSelect.selectByVisibleText(attributeName);
        WebElement attributeItem = attributeSelect.getFirstSelectedOption();
        assertEquals("The attribute " + attributeName + " was not found", attributeName, attributeItem.getText());
        attributeItem.click();

        // Add attribute
        webDriver.findElement(By.xpath("//input[@name='buttonadd" + attributeType + "']")).click();
        Boolean attributeAdded = webDriver.findElements(By.xpath("//td[contains(text(), '" + attributeName + "')]")).size() == 1;
        assertTrue("The attribute " + attributeName + " was not added", attributeAdded);
    }

    private void triggerModifiable(String attributeType, int attributeIndex) {
        webDriver.findElement(By.id("checkboxmodifyable" + attributeType + attributeIndex)).click();
    }

    private void assertAlert() {
        Boolean alertPresent = true;
        try {
            Alert alert = webDriver.switchTo().alert();
            assertEquals("Unexpected alert message: " + alert.getText(), alertMessage, alert.getText());
            alert.accept();
        } catch (NoAlertPresentException e) {
            alertPresent = false;
        }
        assertTrue("Expected an alert but there was none", alertPresent);
    }

    private void inputTestString(String attributeType, int attributeIndex, String testString) {
        WebElement textField = webDriver.findElement(By.xpath("//input[@name='textfield" + attributeType + + attributeIndex + "']"));
        textField.sendKeys(testString);
    }
}
