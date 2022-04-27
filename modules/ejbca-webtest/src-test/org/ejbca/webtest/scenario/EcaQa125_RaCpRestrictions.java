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

import java.util.Collections;

import org.apache.commons.lang.StringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

// TODO Current scenario depends on the success of previous steps, thus, may limit/complicate the discovery of other problems by blocking data prerequisites for next steps. Improve isolation of test data and flows?
/**
 * This test verifies that restrictions in the certificate profile is applied for
 * enrollments through the RA web, using On Server and CSR enrollments.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-125">ECAQA-125</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa125_RaCpRestrictions extends WebTestBase {

    // Helpers
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static RaWebHelper raWebHelper;
    // Test Data
    public static class TestData {
        static final String CERTIFICATE_PROFILE_NAME = "RestrictCP";
        static final String CERTIFICATE_PROFILE_KEY_ALGORITHM = "RSA";
        static final String CERTIFICATE_PROFILE_KEY_BIT_LENGTH = "1024 bits";
        static final String END_ENTITY_PROFILE_NAME = "RestrictEEP";
        static final String[] CERTIFICATE_REQUEST_PEM = {
                "-----BEGIN CERTIFICATE REQUEST-----",
                "MIICZzCCAU8CAQAwIjELMAkGA1UEBhMCVVMxEzARBgNVBAMMClJlc3RyaWN0Q04w",
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwyIsyw3HB+8yxOF9BOfjG",
                "zLoQIX7sLg1lXk1miLyU6wYmuLnZfZrr4pjZLyEr2iP92IE97DeK/8y2827qctPM",
                "y4axmczlRTrEZKI/bVXnLOrQNw1dE+OVHiVoRFa5i4TS/qfhNA/Gy/eKpzxm8LT7",
                "+folAu92HwbQ5H8fWQ/l+ysjTheLMyUDaK83+NvYAL9Gfl29EN/TTrRzLKWoXrlB",
                "Ed7PT2oCBgrvF7pHsrry2O3yuuO2hoF5RQTo9BdBaGvzxGdweYTvdoLWfZm1zGI+",
                "CW0lprBdjagCC4XAcWi5OFcxjrRA9WA6Cu1q4Hn+eJEdCNHVvqss2rz6LOWjAQAr",
                "AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA1JlwrFN4ihTZWICnWFb/kzcmvjcs",
                "0xeerNZQAEk2FJgj+mKVNrqCRWr2iaPpAeggH8wFoZIh7OvhmIZNmxScw4K5HhI9",
                "SZD+Z1Dgkj8+bLAQaxvw8sxXLdizcMNvbaXbzwbAN9OUkXPavBlik/b2JLafcEMM",
                "8IywJOtJMWemfmLgR7KAqDj5520wmXgAK6oAbbMqWUip1vz9oIisv53n2HFq2jzq",
                "a5d2WKBq5pJY19ztQ17HwlGTI8it4rlKYn8p2fDuqxLXiBsX8906E/cFRN5evhWt",
                "zdJ6yvdw3HQsoVAVi0GDHTs2E8zWFoYyP0byzKSSvkvQR363LQ0bik4cuQ==",
                "-----END CERTIFICATE REQUEST-----"
        };
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_RestrictCP_CertificateProfile() {
        // Add Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        // Set 'Available Key Algorithms' and 'Available Bit Lengths'
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.editCertificateProfile(
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_KEY_ALGORITHM),
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_KEY_BIT_LENGTH)
        );
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepB_RestrictEEP_EndEntityProfile() {
        // Add End Entity Profile
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        // Set Certificate Profile in EEP
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.editEndEntityProfile(
                TestData.CERTIFICATE_PROFILE_NAME,
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_NAME),
                getCaName(),
                Collections.singletonList(getCaName())
        );
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepC_KeyPairOnServer() throws InterruptedException {
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        // Make sure 'Provide request info' only contains 'CN, Common Name'
        raWebHelper.assertCorrectProvideRequestInfoBlock();
        // Make sure 'Provide User Credentials' only contains 'Username', 'Enrollment code', 'Confirm enrollment code' and 'Email'
        raWebHelper.assertCorrectProvideUserCredentialsBlock();
        // Click 'Show details' to display Certificate Profile and Key Algorithm
        raWebHelper.clickShowDetailsButton();
        // Assure that the correct values for Certificate Profile and Key Algorithm are selected and that their selections are disabled
        raWebHelper.assertCertificateProfileSelection(
                TestData.CERTIFICATE_PROFILE_NAME + " (default)",
                false
        );
        raWebHelper.assertKeyAlgorithmSelection(
                TestData.CERTIFICATE_PROFILE_KEY_ALGORITHM + " " + TestData.CERTIFICATE_PROFILE_KEY_BIT_LENGTH,
                false
        );
    }

    @Test
    public void stepD_KeyPairViaCSR() throws InterruptedException {
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationProvided();
        raWebHelper.fillClearCsrText(StringUtils.join(TestData.CERTIFICATE_REQUEST_PEM, "\n"));
        raWebHelper.clickUploadCsrButton();
        // Make sure that there is an error message
        raWebHelper.assertCsrUploadError();
    }
}