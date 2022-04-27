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
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.HashMap;

/**
 * The purpose of this test is to verify that End Entity usernames can't contain whitespace and
 * two different users can be created with the same name, but in different case.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_VerifyEndEntityUsername extends WebTestBase {

    // Helpers
    private static AddEndEntityHelper addEndEntityHelper;

    public static class TestData {
        private static final String END_ENTITY_NAME = "EcaQaTestEndEntity";
        private static final String END_ENTITY_COMMON_NAME = "EcaQaTestEndEntity";
        private static final String END_ENTITY_PASSWORD = "foo123";
        private static final String END_ENTITY_PROFILE_NAME = "EMPTY";
        private static final String END_ENTITY_TOKEN = "User Generated";
        private static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
        private static final String END_ENTITY_NAME_IN_DIFFERENT_CASE = "ecaQaTestEndEntity";
        private static final String END_ENTITY_NAME_WITH_WHITESPACE = "EcaQaTestEndEntity ";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        cleanup();
    }

    @AfterClass
    public static void exit() {
        cleanup();
        afterClass();
    }

    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(EcaQa_VerifyEndEntityUsername.TestData.END_ENTITY_NAME);
        removeEndEntityByUsername(EcaQa_VerifyEndEntityUsername.TestData.END_ENTITY_NAME_IN_DIFFERENT_CASE);
        removeEndEntityByUsername(EcaQa_VerifyEndEntityUsername.TestData.END_ENTITY_NAME_WITH_WHITESPACE);
    }

    @Test
    public void stepA_CreateEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);

        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", TestData.END_ENTITY_PASSWORD);
        fields.put("Confirm Password", TestData.END_ENTITY_PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);

        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.setToken(TestData.END_ENTITY_TOKEN);
        addEndEntityHelper.addEndEntity();

        // Verify that we have added the end entity
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME);
    }

    @Test
    public void stepB_CreateEndEntityWithDifferentCaseUsername() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);

        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME_IN_DIFFERENT_CASE);
        fields.put("Password (or Enrollment Code)", TestData.END_ENTITY_PASSWORD);
        fields.put("Confirm Password", TestData.END_ENTITY_PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);

        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.setToken(TestData.END_ENTITY_TOKEN);
        addEndEntityHelper.addEndEntity();

        // Verify that we have added the end entity
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME_IN_DIFFERENT_CASE);
    }

    @Test
    public void stepC_AttemptToCreateDuplicateEndEntityWithWhitespaceInUsername() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);

        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME_WITH_WHITESPACE);
        fields.put("Password (or Enrollment Code)", TestData.END_ENTITY_PASSWORD);
        fields.put("Confirm Password", TestData.END_ENTITY_PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);

        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.setToken(TestData.END_ENTITY_TOKEN);
        addEndEntityHelper.addEndEntity();

        // Verify that existing end entity was found
        addEndEntityHelper.assertEndEntityExistsAlertMessageDisplayed();
    }
}
