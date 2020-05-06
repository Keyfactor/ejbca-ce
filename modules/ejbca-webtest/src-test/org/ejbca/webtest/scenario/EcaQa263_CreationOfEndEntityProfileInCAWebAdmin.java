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
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test describes a creation of End Entity Profile in CA Web admin.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-263">ECAQA-263</a>
 *
 * @version $Id: EcaQa263_CreationOfEndEntityProfileInCAWebAdmin.java 34938 2020-04-28 14:58:22Z andrey_s_helmes
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa263_CreationOfEndEntityProfileInCAWebAdmin extends WebTestBase {

    // Helpers
    private static EndEntityProfileHelper endEntityProfileHelper;

    // TestData
    public static class TestData {
        static final String END_ENTITY_PROFILE_NAME = "ChaEntityProfile";
        static final String DEFAULT_CA_NAME = "Example Person CA";
        static final String DEFAULT_CP_NAME = "ENDUSER";
        static final String[] CP_NAMES = new String[] {DEFAULT_CP_NAME, "SUBCA"};
        static final String DEFAULT_TOKEN_NAME = "User Generated";
        static final String[] TOKEN_NAMES = new String[]{"User Generated", "P12 file", "JKS file", "PEM file"};
        static final String DN_ATTRIBUTE_COMMON_NAME = "CN, Common name";
        static final String DN_ATTRIBUTE_ORGANIZATION = "O, Organization";
        static final String DN_ATTRIBUTE_COUNTRY = "C, Country (ISO 3166)";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        endEntityProfileHelper = new EndEntityProfileHelper(getWebDriver());
    }

    @AfterClass
    public static void exit() {
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_AddEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void stepB_AddAttributes() {
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.triggerEndEntityEmailCheckBox();
        // CN, Common name present by default
        endEntityProfileHelper.assertSubjectDnAttributesRequiredCheckboxIsChecked(TestData.DN_ATTRIBUTE_COMMON_NAME, true);
        endEntityProfileHelper.assertSubjectDnAttributesModifiableCheckboxIsChecked(TestData.DN_ATTRIBUTE_COMMON_NAME, true);
        endEntityProfileHelper.assertSubjectDnAttributesValidationCheckboxIsChecked(TestData.DN_ATTRIBUTE_COMMON_NAME, false);
        // O, Organization
        endEntityProfileHelper.addSubjectDnAttribute(TestData.DN_ATTRIBUTE_ORGANIZATION);
        endEntityProfileHelper.subjectDnAttributeRequiredCheckboxTrigger(TestData.DN_ATTRIBUTE_ORGANIZATION);
        endEntityProfileHelper.assertSubjectDnAttributesRequiredCheckboxIsChecked(TestData.DN_ATTRIBUTE_ORGANIZATION, true);
        endEntityProfileHelper.assertSubjectDnAttributesModifiableCheckboxIsChecked(TestData.DN_ATTRIBUTE_ORGANIZATION, true);
        endEntityProfileHelper.assertSubjectDnAttributesValidationCheckboxIsChecked(TestData.DN_ATTRIBUTE_ORGANIZATION, false);
        // C, Country (ISO 3166)
        endEntityProfileHelper.addSubjectDnAttribute(TestData.DN_ATTRIBUTE_COUNTRY);
        endEntityProfileHelper.subjectDnAttributeRequiredCheckboxTrigger(TestData.DN_ATTRIBUTE_COUNTRY);
        endEntityProfileHelper.assertSubjectDnAttributesRequiredCheckboxIsChecked(TestData.DN_ATTRIBUTE_COUNTRY, true);
        endEntityProfileHelper.assertSubjectDnAttributesModifiableCheckboxIsChecked(TestData.DN_ATTRIBUTE_COUNTRY, true);
        endEntityProfileHelper.assertSubjectDnAttributesValidationCheckboxIsChecked(TestData.DN_ATTRIBUTE_COUNTRY, false);
    }

    @Test
    public void stepC_ManageCertificateProfiles() {
        endEntityProfileHelper.selectDefaultCp(TestData.DEFAULT_CP_NAME);
        endEntityProfileHelper.selectAvailableCps(TestData.CP_NAMES);
        //
        endEntityProfileHelper.assertDefaultCertificateProfileNameSelected(TestData.DEFAULT_CP_NAME);
        endEntityProfileHelper.assertAvailableCertificateProfilesNamesSelected(TestData.CP_NAMES);
    }

    @Test
    public void stepD_ManageCAs() {
        endEntityProfileHelper.selectDefaultCa(TestData.DEFAULT_CA_NAME);
        //
        endEntityProfileHelper.assertDefaultCaNameSelected(TestData.DEFAULT_CA_NAME);
    }

    @Test
    public void stepE_ManageTokens() {
        endEntityProfileHelper.assertDefaultTokenNameSelected(TestData.DEFAULT_TOKEN_NAME);
        endEntityProfileHelper.assertAvailableTokensNamesSelected(TestData.TOKEN_NAMES);
    }

    @Test
    public void stepG_Save() {
        endEntityProfileHelper.saveEndEntityProfile();
    }
}