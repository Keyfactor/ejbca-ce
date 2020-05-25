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

import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.ApprovalProfilesHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.ValidatorsHelper;
import org.ejbca.webtest.util.TestFileResource;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Asserts whether the blacklist validator permits a site based on the
 * blacklist.txt file using base domains.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-201">ECAQA-201</a>
 *
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa201_PositiveBlacklistBaseDomains extends WebTestBase {

    // Helpers
    private static ValidatorsHelper validatorsHelper;
    private static CaHelper caHelper;
    private static ApprovalProfilesHelper approvalProfilesHelperDefault;
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static RaWebHelper raWebHelper;

    // Test Data
    private static class TestData {
        static final String VALIDATOR_BLACKLIST_FILENAME = new TestFileResource("Blacklist.txt").getFileAbsolutePath();
        static final String VALIDATOR_NAME = "EcaQa201-2A_Blacklist";
        static final String VALIDATOR_BLACKLIST_SITE = "www.yahoo.com";
        static final String VALIDATOR_PERFORM_TYPE = "Base domains";
        static final String CA_NAME = "EcaQa201-2A_CA";
        static final String CA_VALIDITY = "1y";
        static final String APPROVAL_PROFILE_NAME = "EcaQa201-2A_ApprovalProfile";
        static final String APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL = "Partitioned Approval";
        static final String CERTIFICATE_PROFILE_NAME = "EcaQa201-2A-CertificateProfile";
        static final String ROLE_NAME = "Super Administrator Role";
        static final String ENTITY_NAME = "EcaQa201-2A_EntityProfile";
        static final String[] CERTIFICATE_REQUEST_PEM = new String[] {
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
        Date currentDate = new Date();
        Calendar oneMonthsFromNow = Calendar.getInstance();
        oneMonthsFromNow.setTime(currentDate);
        oneMonthsFromNow.add(Calendar.MONTH, 1);
        WebDriver webDriver = getWebDriver();

        // Init helpers
        validatorsHelper = new ValidatorsHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        approvalProfilesHelperDefault = new ApprovalProfilesHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        eeProfileHelper = new EndEntityProfileHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // super
        afterClass();
        // Remove generated artifacts
        removeEndEntityProfileByName(TestData.ENTITY_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeApprovalProfileByName(TestData.APPROVAL_PROFILE_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
        removeValidatorByName(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepA_AddAValidator() {
        validatorsHelper.openPage(getAdminWebUrl());
        validatorsHelper.addValidator(TestData.VALIDATOR_NAME);
        validatorsHelper.assertValidatorNameExists(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepB_EditAValidatorWithBlacklist() {
        validatorsHelper.openPage(getAdminWebUrl());
        validatorsHelper.openEditValidatorPage(TestData.VALIDATOR_NAME);
        validatorsHelper.setValidatorType(ValidatorsHelper.ValidatorType.DOMAIN_BLACKLIST_VALIDATOR);
        validatorsHelper.setBlacklistPerformOption(TestData.VALIDATOR_PERFORM_TYPE);
        validatorsHelper.setBlacklistFile(TestData.VALIDATOR_BLACKLIST_FILENAME);
    }

    @Test
    public void stepC_SaveValidator() {
        validatorsHelper.saveValidator();
    }

    @Test
    public void stepD_EditValidatorSecondTime() {
        validatorsHelper.openPage(getAdminWebUrl());
        validatorsHelper.openEditValidatorPage(TestData.VALIDATOR_NAME);
        validatorsHelper.setBlackListSite(TestData.VALIDATOR_BLACKLIST_SITE);

        //Test to verify it returns a positive test result
        validatorsHelper.testBlacklistSite();
        validatorsHelper.assertBlackListResultsIsCorrect("Domain Blacklist Validator '" + TestData.VALIDATOR_NAME + "' permitted issuance of certificate.");
    }

    @Test
    public void stepE_SaveValidatorSecondTime() {
        validatorsHelper.saveValidator();
        validatorsHelper.assertValidatorNameExists(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepF_CreateCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.checkEnforceUniquePublicKeys(false);
        caHelper.checkEnforceUniqueDN(false);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setOtherData(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepG_SaveCA() {
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepH_AddApprovalProfile() {
        approvalProfilesHelperDefault.openPage(getAdminWebUrl());
        approvalProfilesHelperDefault.addApprovalProfile(TestData.APPROVAL_PROFILE_NAME);
    }

    @Test
    public void stepI_EditApprovalProfile() {
        approvalProfilesHelperDefault.openEditApprovalProfilePage(TestData.APPROVAL_PROFILE_NAME);
        approvalProfilesHelperDefault.setApprovalProfileType(TestData.APPROVAL_PROFILE_TYPE_PARTITIONED_APPROVAL);
        approvalProfilesHelperDefault.setApprovalStepPartitionApprovePartitionRole(0, 0,
                TestData.ROLE_NAME);
    }

    @Test
    public void stepJ_SaveApprovalProfile() {
        approvalProfilesHelperDefault.saveApprovalProfile();
    }

    @Test
    public void stepK_AddCertificateProfile() {
        // Add Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void stepL_EditCertificateProfile() {
        // Edit certificate Profile
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);

        // Set Approval Settings
        certificateProfileHelper.selectApprovalSetting(CertificateProfileHelper.ApprovalSetting.ADD_OR_EDIT_END_ENTITY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.selectApprovalSetting(CertificateProfileHelper.ApprovalSetting.KEY_RECOVERY, TestData.APPROVAL_PROFILE_NAME);
        certificateProfileHelper.selectApprovalSetting(CertificateProfileHelper.ApprovalSetting.REVOCATION, TestData.APPROVAL_PROFILE_NAME);

        // Set validity
        certificateProfileHelper.fillValidity("720d");
    }

    @Test
    public void stepM_SaveCertificateProfile() {
        // Save
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepN_AddEndEntityProfile() {
        eeProfileHelper.openPage(getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.ENTITY_NAME);
    }

    @Test
    public void stepO_EditEntityProfile() {
        eeProfileHelper.openEditEndEntityProfilePage(TestData.ENTITY_NAME);
        eeProfileHelper.selectDefaultCa(this.getCaName());
        //Add DNS Name
        eeProfileHelper.setSubjectAlternativeName("DNS Name");
    }

    @Test
    public void stepP_SaveEntityProfile() {
        eeProfileHelper.saveEndEntityProfile(true);
    }

    @Test
    public void stepQ_MakeNewCertificate() throws InterruptedException {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
    }

    @Test
    public void stepR_SelectRequestTemplate() throws Exception {
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.ENTITY_NAME);
        raWebHelper.selectCertificationAuthorityByName(TestData.CA_NAME);
        raWebHelper.selectKeyPairGenerationProvided();
    }

    @Test
    public void stepS_insertCsrCertificate() {
        raWebHelper.fillClearCsrText(StringUtils.join(TestData.CERTIFICATE_REQUEST_PEM, "\n"));
    }

    @Test
    public void stepT_UploadCSRCertificate() {
        raWebHelper.clickUploadCsrButton();
    }

    @Test
    public void stepU_ProvideRequestInfo() {
        raWebHelper.fillMakeRequestEditCommonName("cn" + Calendar.getInstance().toString());
        raWebHelper.fillDnsName(TestData.VALIDATOR_BLACKLIST_SITE);
    }

    @Test
    public void stepV_downloadPem() {
        raWebHelper.clickDownloadPem();
        raWebHelper.assertApproveMessageDoesNotExist();
    }

}
