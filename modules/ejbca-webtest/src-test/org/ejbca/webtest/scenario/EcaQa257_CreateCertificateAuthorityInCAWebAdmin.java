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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa257_CreateCertificateAuthorityInCAWebAdmin extends WebTestBase {
    //Helpers
    private static CaHelper caHelper;
    private static WebDriver webDriver;

    //TestData
    private static final String CA_NAME = "CHASubCA";
    private static final String SUBJECT_DN = "CN=CHASubCA,O=Primekey,C=SE";
    private static final String SIGN_CA = "ManagementCA";
    private static final String CERTIFICATE_PROFILE = "SUBCA";
    private static final String VALIDITY = "10y3mo";
    private static final String POLICY_ID = "2.5.29.32.0";
    private static final String CRL_EXPIRE_PERIOD = "1d";
    private static final String CRL_ISSUE_INTERVAL = "1d";
    private static final String CRL_OVERLAP_TIME = "0m";

    private static final String DELETE_MESSAGE = "Are you sure you want to delete the CA CHASubCA? You should revoke the CA instead if you already have used it to issue certificates.";

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        caHelper = new CaHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void testA_AddCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(CA_NAME);
    }

    @Test
    public void testB_InsertTestData() {
        caHelper.setSubjectDn(SUBJECT_DN);
        caHelper.setSignedBy(SIGN_CA);
        caHelper.setCertificateProfile(CERTIFICATE_PROFILE);
        caHelper.setValidity(VALIDITY);
        caHelper.setPolicyID(POLICY_ID);
        caHelper.setCrlPeriod(CRL_EXPIRE_PERIOD);
        caHelper.setCrlIssueInterval(CRL_ISSUE_INTERVAL);
        caHelper.setCrlOverlapTime(CRL_OVERLAP_TIME);
    }

    @Test
    public void testC_CreateCa() {
        caHelper.createCa();
        caHelper.assertExists(CA_NAME);
    }

    @Test
    public void testD_DeleteCa() {
        caHelper.deleteCaAndAssert(DELETE_MESSAGE, true, false, "CHASubCA", CA_NAME);
    }
}
