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
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Arrays;
import java.util.Collections;

// TODO Current scenario depends on the success of previous steps, thus, may limit/complicate the discovery of other problems by blocking data prerequisites for next steps. Improve isolation of test data and flows?
/**
 * Test to verify that Certificate Profile management operations work as expected.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-12">ECAQA-12</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa12_CPManagement extends WebTestBase {

    // Helpers
    private static AuditLogHelper auditLogHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    // Test Data
    private static class TestData {
        static final String CERTIFICATE_PROFILE_NAME = "ECAQA-12-CertificateProfile";
        static final String CERTIFICATE_PROFILE_NAME_RENAME = "ECAQA-12-CertificateProfile-Renamed";
        static final String CERTIFICATE_PROFILE_NAME_CLONE = "ECAQA-12-CertificateProfile-Cloned";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME_RENAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_add_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Add Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Create",
                "Success",
                null,
                Collections.singletonList("New certificate profile " + TestData.CERTIFICATE_PROFILE_NAME + " added successfully.")
        );
    }

    @Test
    public void stepB_edit_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Edit certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Set validity
        certificateProfileHelper.fillValidity("720d");
        // Save
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME + ".",
                        "changed:encodedvalidity=1y 11mo 25d"
                )
        );
    }

    @Test
    public void stepC_rename_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Rename the Certificate Profile and assert success
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.renameCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME, TestData.CERTIFICATE_PROFILE_NAME_RENAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Rename",
                "Success",
                null,
                Collections.singletonList("Renamed certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME + " to " + TestData.CERTIFICATE_PROFILE_NAME_RENAME + ".")
        );
    }

    @Test
    public void stepD_clone_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Clone the Certificate Profile and assert success
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.cloneCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_RENAME, TestData.CERTIFICATE_PROFILE_NAME_CLONE);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Create",
                "Success",
                null,
                Collections.singletonList("New certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME_CLONE +  " added using profile " + TestData.CERTIFICATE_PROFILE_NAME_RENAME + " as template.")
        );
    }

    @Test
    public void stepE_delete_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Delete the Certificate Profile and cancel
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.deleteCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_CLONE);
        certificateProfileHelper.confirmCertificateProfileDeletion(false, TestData.CERTIFICATE_PROFILE_NAME_CLONE);
        // Delete the Certificate Profile and confirm
        certificateProfileHelper.deleteCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME_CLONE);
        certificateProfileHelper.confirmCertificateProfileDeletion(true, TestData.CERTIFICATE_PROFILE_NAME_CLONE);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Remove",
                "Success",
                null,
                Collections.singletonList("Removed profile " + TestData.CERTIFICATE_PROFILE_NAME_CLONE + ".")
        );
    }

}