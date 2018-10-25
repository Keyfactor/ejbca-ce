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
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

// TODO Current scenario depends on the success of previous steps, thus, may limit/complicate the discovery of other problems by blocking data prerequisites for next steps. Improve isolation of test data and flows?
/**
 * Automated web test for ECAQA-138, which has the purpose of verifying that
 * an EEP with empty attributes that are non-modifiable cannot be saved.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-138">ECAQA-138</a>
 * 
 * @version $Id: EcaQa138_EEPAttributes.java 30091 2018-10-12 14:47:14Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa138_EEPAttributes extends WebTestBase {

    // Helpers
    private static EndEntityProfileHelper endEntityProfileHelper;
    // Test Data
    private static class TestData {
        static final String END_ENTITY_PROFILE_NAME = "ECAQA-138-EndEntityProfile";
        static final String ALERT_MESSAGE_EMPTY_NONMODIFIABLE_ATTRIBUTE = "An empty attribute cannot be non-modifiable.";
        //
        static final String SUBJECT_DN_ATTRIBUTE = "subjectdn";
        static final int SUBJECT_DN_ATTRIBUTE_INDEX = 1;
        static final String SUBJECT_DN_ATTRIBUTE_NAME = "O, Organization";
        static final String SUBJECT_DN_ATTRIBUTE_VALUE = "TestOrg";
        //
        static final String SUBJECT_ALT_NAME_ATTRIBUTE = "subjectaltname";
        static final int SUBJECT_ALT_NAME_ATTRIBUTE_INDEX = 0;
        static final String SUBJECT_ALT_NAME_ATTRIBUTE_NAME = "MS UPN, User Principal Name";
        static final String SUBJECT_ALT_NAME_ATTRIBUTE_VALUE = "testdomain.com";
        //
        static final String SUBJECT_DIR_ATTRIBUTE = "subjectdirattr";
        static final int SUBJECT_DIR_ATTRIBUTE_INDEX = 0;
        static final String SUBJECT_DIR_ATTRIBUTE_NAME = "Place of birth";
        static final String SUBJECT_DIR_ATTRIBUTE_VALUE = "Stockholm";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_addEEP() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void stepB_subjectDn() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.addSubjectAttribute(TestData.SUBJECT_DN_ATTRIBUTE, TestData.SUBJECT_DN_ATTRIBUTE_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        // Uncheck Modifiable and save (should fail, not allowed to save empty non-modifiable attributes)
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.assertSubjectAttributeExists(TestData.SUBJECT_DN_ATTRIBUTE_NAME);
        endEntityProfileHelper.triggerSubjectAttributesAttributeModifiable(TestData.SUBJECT_DN_ATTRIBUTE, TestData.SUBJECT_DN_ATTRIBUTE_INDEX);
        endEntityProfileHelper.saveEndEntityProfile(false);
        endEntityProfileHelper.assertSubjectAttributesAttributeModifiableAlert(TestData.ALERT_MESSAGE_EMPTY_NONMODIFIABLE_ATTRIBUTE, true);
        // Add the test string to the attribute and save (should succeed)
        endEntityProfileHelper.fillSubjectAttributesAttributeValue(
                TestData.SUBJECT_DN_ATTRIBUTE,
                TestData.SUBJECT_DN_ATTRIBUTE_INDEX,
                TestData.SUBJECT_DN_ATTRIBUTE_VALUE
        );
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepC_subjectAltName() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.addSubjectAttribute(TestData.SUBJECT_ALT_NAME_ATTRIBUTE, TestData.SUBJECT_ALT_NAME_ATTRIBUTE_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        // Uncheck Modifiable and save (should fail, not allowed to save empty non-modifiable attributes)
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.assertSubjectAttributeExists(TestData.SUBJECT_ALT_NAME_ATTRIBUTE_NAME);
        endEntityProfileHelper.triggerSubjectAttributesAttributeModifiable(TestData.SUBJECT_ALT_NAME_ATTRIBUTE, TestData.SUBJECT_ALT_NAME_ATTRIBUTE_INDEX);
        endEntityProfileHelper.saveEndEntityProfile(false);
        endEntityProfileHelper.assertSubjectAttributesAttributeModifiableAlert(TestData.ALERT_MESSAGE_EMPTY_NONMODIFIABLE_ATTRIBUTE, true);
        // Add the test string to the attribute and save (should succeed)
        endEntityProfileHelper.fillSubjectAttributesAttributeValue(
                TestData.SUBJECT_ALT_NAME_ATTRIBUTE,
                TestData.SUBJECT_ALT_NAME_ATTRIBUTE_INDEX,
                TestData.SUBJECT_ALT_NAME_ATTRIBUTE_VALUE
        );
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepD_subjectDir() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.addSubjectAttribute(TestData.SUBJECT_DIR_ATTRIBUTE, TestData.SUBJECT_DIR_ATTRIBUTE_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        // Uncheck Modifiable and save (should fail, not allowed to save empty non-modifiable attributes)
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.assertSubjectAttributeExists(TestData.SUBJECT_DIR_ATTRIBUTE_NAME);
        endEntityProfileHelper.triggerSubjectAttributesAttributeModifiable(TestData.SUBJECT_DIR_ATTRIBUTE, TestData.SUBJECT_DIR_ATTRIBUTE_INDEX);
        endEntityProfileHelper.saveEndEntityProfile(false);
        endEntityProfileHelper.assertSubjectAttributesAttributeModifiableAlert(TestData.ALERT_MESSAGE_EMPTY_NONMODIFIABLE_ATTRIBUTE, true);
        // Add the test string to the attribute and save (should succeed)
        endEntityProfileHelper.fillSubjectAttributesAttributeValue(
                TestData.SUBJECT_DIR_ATTRIBUTE,
                TestData.SUBJECT_DIR_ATTRIBUTE_INDEX,
                TestData.SUBJECT_DIR_ATTRIBUTE_VALUE
        );
        endEntityProfileHelper.saveEndEntityProfile();
    }

}
