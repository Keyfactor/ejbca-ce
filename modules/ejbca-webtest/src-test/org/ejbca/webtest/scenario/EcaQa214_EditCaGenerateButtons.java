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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.log4j.Logger;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;


/**
 * Tests the 'Generate' buttons on the Edit CA page, both when adding a new CA and when
 * editing an existing CA.
 *
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa214_EditCaGenerateButtons extends WebTestBase {
    
    private static final Logger log = Logger.getLogger(EcaQa214_EditCaGenerateButtons.class);

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;


    // Test Data
    private static class TestData {
        private static final String CA_NAME = "GenButtonsCA";
        private static final String SUBJECT_DN_1 = "CN=ABC";
        private static final String SUBJECT_DN_2 = "CN=DEF";
        private static final String SUBJECT_DN_3 = "CN=GHI";
        private static final String EXPECTED_FIRST_ERROR = "Ca Validity: Validation Error: Value is required.";
        public static final String SUBJECT_DN_EXISTING_CA = "CN=JKL";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
        // Verify a cryptotoken exists
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists(getManagementCACryptoTokenName());
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.CA_NAME);
        // super
        afterClass();
    }
    
    private void assertInputFieldValues(final String subjectDn, final String partitionSuffix) {
        try {
            final String encodedSubjectDn = URLEncoder.encode(subjectDn, "US-ASCII");
            caHelper.assertDefaultCrlDistributionPointUri(getPublicWebUrl() + "publicweb/webdist/certdist?cmd=crl&issuer=" + encodedSubjectDn + partitionSuffix);
            caHelper.assertDefaultCrlIssuer(subjectDn);
            caHelper.assertDefaultFreshestCrlDistributionPointUri(getPublicWebUrl() + "publicweb/webdist/certdist?cmd=deltacrl&issuer=" + encodedSubjectDn + partitionSuffix);
            caHelper.assertOcspServiceDefaultUri(getPublicWebUrl() + "publicweb/status/ocsp");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void stepA_openAddCaPage() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
    }
    

    /** Tests the 'Generate' buttons when creating a new CA after having modified the Subject DN */
    @Test
    public void stepB_generateWithModifiedSubjectDn() {
        // Given
        caHelper.setSubjectDn(TestData.SUBJECT_DN_1);
        // When
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.clickGenerateDefaultCrlIssuer();
        caHelper.clickGenerateDefaultFreshestCrlDistributionPoint();
        caHelper.clickGenerateOcspServiceDefaultUri();
        // Then
        caHelper.waitForOcspServiceDefaultUri();
        assertInputFieldValues(TestData.SUBJECT_DN_1, "");
    }

    /** Tests the 'Generate' buttons when creating a new CA after having enabled CRL partitions and then modified the Subject DN */
    @Test
    public void stepC_generateWithCrlPartitions() {
        // Given
        caHelper.clearDefaultCaDefinedValidationData();
        caHelper.checkUseCrlPartitions(true);
        caHelper.setSubjectDn(TestData.SUBJECT_DN_2);
        // When
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.clickGenerateDefaultCrlIssuer();
        caHelper.clickGenerateDefaultFreshestCrlDistributionPoint();
        caHelper.clickGenerateOcspServiceDefaultUri();
        // Then
        caHelper.waitForOcspServiceDefaultUri();
        assertInputFieldValues(TestData.SUBJECT_DN_2, "&partition=*");
    }

    /** Tests the 'Generate' buttons when creating a new CA when there are error messages visible */
    @Test
    public void stepD_generateWithErrorMessages() {
        // Given
        caHelper.clearDefaultCaDefinedValidationData();
        caHelper.createCa(); // will trigger validation errors
        caHelper.assertHasErrorMessage(TestData.EXPECTED_FIRST_ERROR);
        caHelper.setSubjectDn(TestData.SUBJECT_DN_3);
        // When
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.clickGenerateDefaultCrlIssuer();
        caHelper.clickGenerateDefaultFreshestCrlDistributionPoint();
        caHelper.clickGenerateOcspServiceDefaultUri();
        // Then
        caHelper.waitForOcspServiceDefaultUri();
        assertInputFieldValues(TestData.SUBJECT_DN_3, "&partition=*");
    }
    
    @Test
    public void stepF_generateWithExistingCa() {
        // Given
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setCryptoToken(getManagementCACryptoTokenName());
        caHelper.setSubjectDn(TestData.SUBJECT_DN_EXISTING_CA);
        caHelper.setValidity("1h");
        caHelper.createCa();
        // When
        caHelper.edit(TestData.CA_NAME);
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.clickGenerateDefaultCrlIssuer();
        caHelper.clickGenerateDefaultFreshestCrlDistributionPoint();
        caHelper.clickGenerateOcspServiceDefaultUri();
        // Then
        caHelper.waitForOcspServiceDefaultUri();
        assertInputFieldValues(TestData.SUBJECT_DN_EXISTING_CA, "");
    }
}
