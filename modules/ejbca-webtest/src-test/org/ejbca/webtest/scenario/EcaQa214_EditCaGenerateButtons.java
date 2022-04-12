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
import java.util.Arrays;

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
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-214">ECAQA-214</a>
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa214_EditCaGenerateButtons extends WebTestBase {
    
    // Helpers
    private static CaHelper caHelper;

    // Test Data
    private static class TestData {
        static final String CA_NAME = "GenButtonsCA";
        static final String SUBJECT_DN_1 = "CN=ABC";
        static final String SUBJECT_DN_2 = "CN=DEF";
        static final String SUBJECT_DN_3 = "CN=GHI";
        static final String EXPECTED_1ST_ERROR = "Ca Validity: Validation Error: Value is required.";
        static final String EXPECTED_2ND_ERROR = "Microsoft CA Compatibility Mode or Partitioned CRLs are not allowed without 'Issuing Distribution Point on CRL'.";
        static final String EXPECTED_3RD_ERROR = "Microsoft CA Compatibility Mode or Partitioned CRLs are not allowed without a 'Default CRL Distribution Point' filled in, which must contain an asterisk (*) as a placeholder for the partition number.";
        static final String SUBJECT_DN_EXISTING_CA = "CN=JKL";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        CryptoTokenHelper cryptoTokenHelper = new CryptoTokenHelper(webDriver);
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
        caHelper.assertHasErrorMessages(Arrays.asList(
                TestData.EXPECTED_1ST_ERROR,
                TestData.EXPECTED_2ND_ERROR,
                TestData.EXPECTED_3RD_ERROR
        ));
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
