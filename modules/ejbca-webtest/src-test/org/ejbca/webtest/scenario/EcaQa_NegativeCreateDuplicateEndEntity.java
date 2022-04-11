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
 * The purpose of this test is to verify that duplicate End Entities cannot be created
 * using different uppercase/lowercase letters or whitespaces in usernames.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_NegativeCreateDuplicateEndEntity extends WebTestBase {

    // Helpers
    private static AddEndEntityHelper addEndEntityHelper;

    public static class TestData {
        private static final String END_ENTITY_NAME = "EcaQaTestEndEntity";
        private static final String END_ENTITY_COMMON_NAME = "EcaQaTestEndEntity";
        private static final String END_ENTITY_PASSWORD = "foo123";
        private static final String END_ENTITY_PROFILE_NAME = "EMPTY";
        private static final String END_ENTITY_TOKEN = "User Generated";
        private static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
        private static final String DUPLICATE_END_ENTITY_NAME_1 = "ecaQaTestEndEntity";
        private static final String DUPLICATE_END_ENTITY_NAME_2 = "EcaQaTestEndEntity ";
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
        removeEndEntityByUsername(EcaQa_NegativeCreateDuplicateEndEntity.TestData.END_ENTITY_NAME);
        removeEndEntityByUsername(EcaQa_NegativeCreateDuplicateEndEntity.TestData.DUPLICATE_END_ENTITY_NAME_1);
        removeEndEntityByUsername(EcaQa_NegativeCreateDuplicateEndEntity.TestData.DUPLICATE_END_ENTITY_NAME_2);
    }

    @Test
    public void stepA_CreateOriginalEndEntity() {
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
    public void stepB_AttemptToCreateEndEntityWithDifferentCaseUsername() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);

        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.DUPLICATE_END_ENTITY_NAME_1);
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

    @Test
    public void stepC_AttemptToCreateEndEntityWithWhitespaceInUsername() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);

        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.DUPLICATE_END_ENTITY_NAME_2);
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
