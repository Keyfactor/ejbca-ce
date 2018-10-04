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

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * Test to verify that Certificate Profile management operations work as expected.
 * 
 * @version $Id: EcaQa12_CPManagement.java 28911 2018-05-11 06:48:28Z oskareriksson $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa12_CPManagement extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private static final String cpName = "TestCertificateProfile";
    private static final String cpRename = "TestCertificateProfileNew";
    private static final String cpClone = "ClonedTestCertificateProfile";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        certificateProfileSession.removeCertificateProfile(admin, cpName);
        certificateProfileSession.removeCertificateProfile(admin, cpRename);
        tearDown();
    }

//    @Test
//    public void testA_addCP() {
//        AuditLogHelper.resetFilterTime();
//
//        // Add Certificate Profile
//        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
//        CertificateProfileHelper.add(webDriver, cpName, true);
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Create", "Success", null,
//                Arrays.asList("New certificate profile " + cpName + " added successfully."));
//    }

//    @Test
//    public void testB_editCP() {
//        AuditLogHelper.resetFilterTime();
//
//        // Edit certificate Profile
//        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
//        CertificateProfileHelper.edit(webDriver, cpName);
//
//        // Set validity and save
//        WebElement validity = webDriver.findElement(By.id("cpf:textfieldvalidity"));
//        validity.clear();
//        validity.sendKeys("720d");
//        CertificateProfileHelper.save(webDriver, true);
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.reload(webDriver);
//        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Edit", "Success", null,
//                Arrays.asList("msg=Edited certificateprofile " + cpName + ".", "changed:encodedvalidity=1y 11mo 25d"));
//    }

//    @Test
//    public void testC_renameCP() {
//        AuditLogHelper.resetFilterTime();
//
//        // Rename the Certificate Profile and assert success
//        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
//        CertificateProfileHelper.rename(webDriver, cpName, cpRename);
//        CertificateProfileHelper.assertExists(webDriver, cpRename);
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.reload(webDriver);
//        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Rename", "Success", null,
//                Arrays.asList("Renamed certificateprofile " + cpName + " to " + cpRename + "."));
//    }

//    @Test
//    public void testD_cloneCP() {
//        AuditLogHelper.resetFilterTime();
//
//        // Rename the Certificate Profile and assert success
//        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
//        CertificateProfileHelper.clone(webDriver, cpRename, cpClone);
//        CertificateProfileHelper.assertExists(webDriver, cpClone);
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.reload(webDriver);
//        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Create", "Success", null,
//                Arrays.asList("New certificateprofile " + cpClone +  " added using profile " + cpRename + " as template."));
//    }

//    @Test
//    public void testE_deleteCP() {
//        AuditLogHelper.resetFilterTime();
//
//        // Delete the Certificate Profile and cancel
//        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
//        CertificateProfileHelper.delete(webDriver, cpClone, false);
//
//        // Delete the Certificate Profile and confirm
//        CertificateProfileHelper.delete(webDriver, cpClone, true);
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.reload(webDriver);
//        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Remove", "Success", null,
//                Arrays.asList("Removed profile " + cpClone + "."));
//    }
}