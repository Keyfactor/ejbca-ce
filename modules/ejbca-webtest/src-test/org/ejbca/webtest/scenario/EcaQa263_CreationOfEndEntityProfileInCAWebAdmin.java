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
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test describes a creation of End Entity Profile in CA Web admin.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-263">ECAQA-263</a>
 *
 * @version $Id$ EcaQa263_CreationOfEndEntityProfileInCAWebAdmin.java 2020-04-21 15:00 $tobiasM
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa263_CreationOfEndEntityProfileInCAWebAdmin extends WebTestBase {

    // Helpers
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;

    // TestData
    public static class TestData {
        static final String CA_NAME = "EcaQa263_CA";
        static final String CA_VALIDITY = "2y";
        static final String ENTITY_PROFILE_NAME = "EcaQa263_EE";
        static final String DEFAULT_CA_NAME = CA_NAME;
        static final String DN_ATTRIBUTE_ORGANIZATION = "O, Organization";
        static final String DN_ATTRIBUTE_COUNTRY = "C, Country (ISO 3166)";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        caHelper = new CaHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        removeCaAndCryptoToken(TestData.CA_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_AddCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepB_AddEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.ENTITY_PROFILE_NAME);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.ENTITY_PROFILE_NAME);
        endEntityProfileHelper.triggerEndEntityEmailCheckBox();
    }

    @Test
    public void stepC_AddAttributes() {
        endEntityProfileHelper.addSubjectDnAttribute(TestData.DN_ATTRIBUTE_ORGANIZATION);
        endEntityProfileHelper.subjectDnAttributeRequiredBoxTrigger(TestData.DN_ATTRIBUTE_ORGANIZATION);
        endEntityProfileHelper.addSubjectDnAttribute(TestData.DN_ATTRIBUTE_COUNTRY);
        endEntityProfileHelper.subjectDnAttributeRequiredBoxTrigger(TestData.DN_ATTRIBUTE_COUNTRY);
    }

    @Test
    public void stepD_DefaultCaAndSave() {
        endEntityProfileHelper.selectDefaultCa(TestData.DEFAULT_CA_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        endEntityProfileHelper.deleteEndEntityProfile(TestData.ENTITY_PROFILE_NAME);
        endEntityProfileHelper.confirmEndEntityProfileDeletion(true);
    }
}