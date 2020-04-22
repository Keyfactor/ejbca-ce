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

/**
 * This test verifies creation of Subordinate certificate authorities in CA Web admin.
 * <br>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-257">ECAQA-257</a>
 * 
 * @version $Id$ EcaQa257_CreateCertificateAuthorityInCAWebAdmin.java 2020-04-21 15:00 tobiasM$
 *
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa257_CreateCertificateAuthorityInCAWebAdmin extends WebTestBase {
    //Helpers
    private static CaHelper caHelper;

    //TestData
    public static class TestData {
        private static final String CA_NAME = "EcaQa257";
        private static final String SUBJECT_DN = "CN="+CA_NAME+",O=Primekey,C=SE";
        private static final String SIGN_CA = "ManagementCA";
        private static final String CERTIFICATE_PROFILE = "SUBCA";
        private static final String VALIDITY = "10y3mo";
        private static final String POLICY_ID = "2.5.29.32.0";
        private static final String CRL_EXPIRE_PERIOD = "1d";
        private static final String CRL_ISSUE_INTERVAL = "1d";
        private static final String CRL_OVERLAP_TIME = "0m";
        private static final String DELETE_MESSAGE = "Are you sure you want to delete the CA "+CA_NAME+"? You should revoke the CA instead if you already have used it to issue certificates.";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        caHelper = new CaHelper(getWebDriver());
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void stepA_AddCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
    }

    @Test
    public void stepB_InsertTestData() {
        caHelper.setSubjectDn(TestData.SUBJECT_DN);
        caHelper.setSignedBy(TestData.SIGN_CA);
        caHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE);
        caHelper.setValidity(TestData.VALIDITY);
        caHelper.setPolicyID(TestData.POLICY_ID);
        caHelper.setCrlPeriod(TestData.CRL_EXPIRE_PERIOD);
        caHelper.setCrlIssueInterval(TestData.CRL_ISSUE_INTERVAL);
        caHelper.setCrlOverlapTime(TestData.CRL_OVERLAP_TIME);
    }

    @Test
    public void stepC_CreateCa() {
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepD_DeleteCa() {
        caHelper.deleteCaAndAssert(TestData.DELETE_MESSAGE, true, false, "EcaQa257", TestData.CA_NAME);
    }
}