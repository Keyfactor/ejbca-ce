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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.WebTestHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Automated web test for ECAQA-138, which has the purpose of verifying that
 * an EEP with empty attributes that are non-modifiable cannot be saved.
 * 
 * @version $Id: EcaQa138_EEPAttributes.java 28641 2018-04-05 13:36:21Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa138_EEPAttributes extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));
    private static final String eepName = "ECAQA138";

    private static WebDriver webDriver;
    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    // Strings for test
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

//    @Test
//    public void testA_addEEP() {
//        EndEntityProfileHelper.goTo(webDriver, getAdminWebUrl());
//        EndEntityProfileHelper.add(webDriver, eepName, true);
//    }

//    @Test
//    public void testB_subjectDn() {
//        testAttribute(subjectDnBase, subjectDnAttribute, 1, subjectDnString);
//    }

//    @Test
//    public void testC_subjectAltName() {
//        testAttribute(subjectAltNameBase, subjectAltNameAttribute, 0, subjectAltNameString);
//    }

//    @Test
//    public void testC_subjectDirAttr() {
//        testAttribute(subjectDirAttrBase, subjectDirAttrAttribute, 0, subjectDirAttrString);
//    }

//    private void testAttribute(String attributeType, String attributeName, int attributeIndex, String testString) {
//        // Add the attribute, save it with Modifiable checked (should succeed)
//        EndEntityProfileHelper.edit(webDriver, eepName);
//        EndEntityProfileHelper.addAttribute(webDriver, attributeType, attributeName);
//        EndEntityProfileHelper.save(webDriver, true);
//
//        // Uncheck Modifiable and save (should fail, not allowed to save empty non-modifiable attributes)
//        EndEntityProfileHelper.edit(webDriver, eepName);
//        triggerModifiable(attributeType, attributeIndex);
//        EndEntityProfileHelper.save(webDriver, false);
//        WebTestHelper.assertAlert(webDriver, alertMessage, true);
//
//        // Add the test string to the attribute and save (should succeed)
//        inputTestString(attributeType, attributeIndex, testString);
//        EndEntityProfileHelper.save(webDriver, true);
//    }

//    private void triggerModifiable(String attributeType, int attributeIndex) {
//        webDriver.findElement(By.id("checkboxmodifyable" + attributeType + attributeIndex)).click();
//    }

//    private void inputTestString(String attributeType, int attributeIndex, String testString) {
//        WebElement textField = webDriver.findElement(By.xpath("//input[@name='textfield" + attributeType + + attributeIndex + "']"));
//        textField.sendKeys(testString);
//    }
}
