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
import static org.junit.Assert.fail;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.Select;

/**
 * In this test case all possible fields of ENDUSER End Entity with End Entity Profile
 * 'OnHold' are filled in to verify that they work.
 *
 * @version $Id: EcaQa60_EEPOnHold.java 29146 2018-06-07 13:58:01Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa60_EEPOnHold extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityProfileSessionRemote.class);
    private static EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);

    private static WebDriver webDriver;

    private static final String eepName = "OnHold";
    private static final String eeName = "TestEndEntityOnHold";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
        endEntityManagementSession.deleteUser(admin, eeName);
        endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        webDriver.quit();
    }

//    @Test
//    public void testA_addAndEditEep() {
//        EndEntityProfileHelper.goTo(webDriver, getAdminWebUrl());
//        EndEntityProfileHelper.add(webDriver, eepName, true);
//        EndEntityProfileHelper.edit(webDriver, eepName);
//        webDriver.findElement(By.id("checkboxuseissuancerevocationreason")).click();
//        Select selectIssuanceRevocationReason = new Select(webDriver.findElement(By.xpath("//select[@name='selectissuancerevocationreason']")));
//        selectIssuanceRevocationReason.selectByVisibleText("Suspended: Certificate hold");
//        EndEntityProfileHelper.save(webDriver, true);
//    }

//    @Test
//    public void testB_addEndEntity() {
//        // Go to "Add End Entity"
//        webDriver.get(getAdminWebUrl());
//        WebElement addEeLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/ra/addendentity.jsp')]"));
//        addEeLink.click();
//
//        Select dropDownEepPreSelect = new Select(webDriver.findElement(By.xpath("//select[@name='selectendentityprofile']")));
//        dropDownEepPreSelect.selectByVisibleText(eepName);
//
//        try {
//            webDriver.findElement(By.xpath("//input[@name='textfieldusername']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldpassword']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldconfirmpassword']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldemail']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldemaildomain']"));
//            webDriver.findElement(By.xpath("//input[@name='textfieldsubjectdn0']"));
//            webDriver.findElement(By.xpath("//input[@name='buttonadduser']"));
//            webDriver.findElement(By.xpath("//input[@name='buttonreset']"));
//            Select selectCertProfile = new Select(webDriver.findElement(By.xpath("//select[@name='selectcertificateprofile']")));
//            assertEquals("'ENDUSER' was not the preset Certificate Profile", "ENDUSER", selectCertProfile.getFirstSelectedOption().getText());
//            Select selectCa = new Select(webDriver.findElement(By.xpath("//select[@name='selectca']")));
//            selectCa.selectByVisibleText(getCaName());
//            Select selectToken = new Select(webDriver.findElement(By.xpath("//select[@name='selecttoken']")));
//            assertEquals("'User Generated' was not the first selected option in 'Token'", "User Generated",
//                    selectToken.getFirstSelectedOption().getText());
//            // Side step from the ECAQA test but we need it to enroll in RA web.
//            selectToken.selectByVisibleText("P12 file");
//            Select selectIssuanceRecocationReason = new Select(webDriver.findElement(By.xpath("//select[@name='selectissuancerevocationreason']")));
//            assertEquals("'Suspended: Certificate hold' was not preset in 'Revocation reason to set after certificate issuance'",
//                    "Suspended: Certificate hold", selectIssuanceRecocationReason.getFirstSelectedOption().getText());
//        } catch (NoSuchElementException e) {
//            fail("Could not locate element in 'Add End Entity page' when EEP" + eepName + " was selected.\n" + e.getMessage());
//        }
//
//        webDriver.findElement(By.xpath("//input[@name='textfieldusername']")).sendKeys(eeName);
//        webDriver.findElement(By.xpath("//input[@name='textfieldsubjectdn0']")).sendKeys(eeName);
//        webDriver.findElement(By.xpath("//input[@name='textfieldpassword']")).sendKeys("foo123");
//        webDriver.findElement(By.xpath("//input[@name='textfieldconfirmpassword']")).sendKeys("foo123");
//        webDriver.findElement(By.xpath("//input[@name='buttonadduser']")).click();
//
//        WebElement messageInfo = webDriver.findElement(By.xpath("//div[@class='message info']"));
//        assertEquals("Unexpected status text after adding end entity", "End Entity TestEndEntityOnHold added successfully.", messageInfo.getText());
//    }

//    @Test
//    public void testC_verifyEndEntity() {
//        verifyEndEntityOrCertificate("Suspended: Certificate hold", "View End Entity (popup window)");
//    }

//    @Test
//    public void testD_enroll() {
//        webDriver.get(getRaWebUrl() + "enrollwithusername.xhtml");
//        webDriver.findElement(By.id("enrollWithUsernameForm:username")).sendKeys(eeName);
//        webDriver.findElement(By.id("enrollWithUsernameForm:enrollmentCode")).sendKeys("foo123");
//        webDriver.findElement(By.id("enrollWithUsernameForm:checkButton")).click();
//        webDriver.findElement(By.id("enrollWithUsernameForm:generatePkcs12")).click();
//        webDriver.get(getAdminWebUrl());
//        verifyEndEntityOrCertificate("Revocation reasons : Certificate hold", "View Certificates (popup window)");
//    }

//    private void verifyEndEntityOrCertificate(String textToFind, String button) {
//        WebElement searchEeLink = webDriver.findElement(By.xpath("//a[contains(@href,'/ejbca/adminweb/ra/listendentities.jsp')]"));
//        searchEeLink.click();
//        webDriver.findElement(By.xpath("//input[@name='textfieldusername']")).sendKeys(eeName);
//        ;
//        webDriver.findElement(By.xpath("//input[@name='buttonfind']")).click();
//        WebElement resultButtonGroup = webDriver.findElement(By.xpath("//table[@class='actions']"));
//        resultButtonGroup.findElement(By.xpath(".//button[@title='" + button + "']")).click();
//
//        boolean foundElement = false;
//        // Switch to popup
//        final String mainWindow = webDriver.getWindowHandle();
//        for (String window : webDriver.getWindowHandles()) {
//            if (!window.equals(mainWindow)) {
//                webDriver.switchTo().window(window);
//                try {
//                    webDriver.findElement(By.xpath("//*[text()[contains(.,'" + textToFind + "')]]"));
//                    foundElement = true;
//                } catch (NoSuchElementException e) {
//                    continue;
//                }
//                break;
//            }
//        }
//
//        if (!foundElement) {
//            fail("Could not locate '" + textToFind + "' while viewing the created end entity");
//        }
//        webDriver.switchTo().window(mainWindow);
//    }
}
