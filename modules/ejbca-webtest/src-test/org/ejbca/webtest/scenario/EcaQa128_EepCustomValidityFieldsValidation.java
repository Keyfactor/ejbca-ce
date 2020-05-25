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

import org.apache.log4j.Logger;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Tests the text fields 'Custom Validity Start Time' and 'Custom Validity Start Time' in End Entity Profiles.
 * Only the GUI is tested, not actual certificate issuance.
 * <p>
 * The 'Use' checkbox and validation of the text fields is tested.
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa128_EepCustomValidityFieldsValidation extends WebTestBase {

    private static final Logger log = Logger.getLogger(EcaQa128_EepCustomValidityFieldsValidation.class);

    // Helpers
    private static EndEntityProfileHelper endEntityProfileHelper;
    
    // Test Data
    public static class TestData {
        static final String END_ENTITY_PROFILE_NAME = "Test_Validity";
    }
    
    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        // Ensure no test data is left behind from aborted tests
        try {
            cleanup();
        } catch (RuntimeException e) {
            log.error("Clean up failed. This is expected when running against a remote instance without Remote EJB access.", e);
        }
    }
    
    @AfterClass
    public static void exit() {
        cleanup();
        // super
        afterClass();
    }
    
    private static void cleanup() {
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void stepA_addEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void stepB_openEndEntityProfile() {
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.assertUseCustomValidityStartTimeIsSelected(false);
        endEntityProfileHelper.assertCustomValidityStartTimeFieldsEnabled(false);
        endEntityProfileHelper.assertUseCustomValidityEndTimeIsSelected(false);
        endEntityProfileHelper.assertCustomValidityEndTimeFieldsEnabled(false);
    }

    @Test
    public void stepC_editWithBadValue() {
        // Start Time
        endEntityProfileHelper.triggerCertificateValidityStartTime();
        endEntityProfileHelper.assertCustomValidityStartTimeModifiableIsSelected(true);
        endEntityProfileHelper.assertCustomValidityStartTimeFieldsEnabled(true);
        assertEquals("'Custom Validity Start Time' had the wrong value", "", endEntityProfileHelper.getCertificateValidityStartTime());
        endEntityProfileHelper.setCertificateValidityStartTime("***"); // bad date
        // End Time
        endEntityProfileHelper.triggerCertificateValidityEndTime();
        endEntityProfileHelper.assertCustomValidityEndTimeFieldsEnabled(true);
        endEntityProfileHelper.assertCustomValidityEndTimeModifiableIsSelected(true);
        assertEquals("'Custom Validity End Time' had the wrong value", "", endEntityProfileHelper.getCertificateValidityEndTime());
        endEntityProfileHelper.saveEndEntityProfileWithClientSideErrors(); // should not be saved
    }

    @Test
    public void stepD_editWithBlank() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        // Start Time
        endEntityProfileHelper.setUseCertificateValidityStartTime(true);
        endEntityProfileHelper.assertCustomValidityStartTimeModifiableIsSelected(true);
        endEntityProfileHelper.assertCustomValidityStartTimeFieldsEnabled(true);
        assertEquals("'Custom Validity Start Time' had the wrong value", "", endEntityProfileHelper.getCertificateValidityStartTime());
        // End Time
        endEntityProfileHelper.setUseCertificateValidityEndTime(true);
        endEntityProfileHelper.assertCustomValidityEndTimeFieldsEnabled(true);
        endEntityProfileHelper.assertCustomValidityEndTimeModifiableIsSelected(true);
        assertEquals("'Custom Validity End Time' had the wrong value", "", endEntityProfileHelper.getCertificateValidityEndTime());
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepE_editWithDate() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        // Start Time
        endEntityProfileHelper.setUseCertificateValidityStartTime(true);
        endEntityProfileHelper.setCertificateValidityStartTime("2017-06-15");
        // End Time
        endEntityProfileHelper.setUseCertificateValidityEndTime(true);
        endEntityProfileHelper.setCertificateValidityEndTime("2018-06-15");
        endEntityProfileHelper.saveEndEntityProfile();
    }
    
    @Test
    public void stepE_editWithDateTime() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        // Start Time
        endEntityProfileHelper.setUseCertificateValidityStartTime(true);
        endEntityProfileHelper.setCertificateValidityStartTime("2017-06-15 02:00:00+02:00");
        // End Time
        endEntityProfileHelper.setUseCertificateValidityEndTime(true);
        endEntityProfileHelper.setCertificateValidityEndTime("2018-06-15 02:00:00+02:00");
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepE_editWithRelativeTime() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        // Start Time
        endEntityProfileHelper.setUseCertificateValidityStartTime(true);
        endEntityProfileHelper.setCertificateValidityStartTime("10:10:10");
        // End Time
        endEntityProfileHelper.setUseCertificateValidityEndTime(true);
        endEntityProfileHelper.setCertificateValidityEndTime("09:10:10");
        endEntityProfileHelper.saveEndEntityProfile();
    }
}
