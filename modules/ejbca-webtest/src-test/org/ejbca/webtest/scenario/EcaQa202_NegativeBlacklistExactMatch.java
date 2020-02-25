package org.ejbca.webtest.scenario;

import java.util.Calendar;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang.StringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.ValidatorsHelper;
import org.ejbca.webtest.utils.GetResourceDir;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Asserts whether the blacklist validator denies a site based on the
 * blacklist.txt file using exact match.
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa202_NegativeBlacklistExactMatch extends WebTestBase {

    // Helpers
    private static ValidatorsHelper validatorsHelper;
    private static CaHelper caHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static RaWebHelper raWebHelper;

    // Test Data
    private static class TestData {
        private static final String VALIDATOR_NAME = "EcaQa202-2C_Blacklist";
        private static final String VALIDATOR_BLACKLIST_FILENAME = GetResourceDir.getResourceFolder() + "/Blacklist.txt";
        private static final String VALIDATOR_BLACKLIST_SITE = "evil.example.edu";
        private static final String VALIDATOR_PERFORM_TYPE = "Exact match";
        private static final String CA_NAME = "EcaQa202-2C_CA";
        private static final String CA_VALIDITY = "1y";
        private static final String APPROVAL_PROFILE_NAME = "EcaQa202-2C_ApprovalProfile";
        private static final String CERTIFICATE_PROFILE_NAME = "EcaQa202-2C_CertificateProfile";
        private static final String ENTITY_NAME = "EcaQa202-2C_EntityProfile";
        static final String[] CERTIFICATE_REQUEST_PEM = new String[]{"-----BEGIN CERTIFICATE REQUEST-----", "MIICZzCCAU8CAQAwIjELMAkGA1UEBhMCVVMxEzARBgNVBAMMClJlc3RyaWN0Q04w", "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwyIsyw3HB+8yxOF9BOfjG", "zLoQIX7sLg1lXk1miLyU6wYmuLnZfZrr4pjZLyEr2iP92IE97DeK/8y2827qctPM", "y4axmczlRTrEZKI/bVXnLOrQNw1dE+OVHiVoRFa5i4TS/qfhNA/Gy/eKpzxm8LT7", "+folAu92HwbQ5H8fWQ/l+ysjTheLMyUDaK83+NvYAL9Gfl29EN/TTrRzLKWoXrlB", "Ed7PT2oCBgrvF7pHsrry2O3yuuO2hoF5RQTo9BdBaGvzxGdweYTvdoLWfZm1zGI+", "CW0lprBdjagCC4XAcWi5OFcxjrRA9WA6Cu1q4Hn+eJEdCNHVvqss2rz6LOWjAQAr", "AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA1JlwrFN4ihTZWICnWFb/kzcmvjcs", "0xeerNZQAEk2FJgj+mKVNrqCRWr2iaPpAeggH8wFoZIh7OvhmIZNmxScw4K5HhI9", "SZD+Z1Dgkj8+bLAQaxvw8sxXLdizcMNvbaXbzwbAN9OUkXPavBlik/b2JLafcEMM", "8IywJOtJMWemfmLgR7KAqDj5520wmXgAK6oAbbMqWUip1vz9oIisv53n2HFq2jzq", "a5d2WKBq5pJY19ztQ17HwlGTI8it4rlKYn8p2fDuqxLXiBsX8906E/cFRN5evhWt", "zdJ6yvdw3HQsoVAVi0GDHTs2E8zWFoYyP0byzKSSvkvQR363LQ0bik4cuQ==", "-----END CERTIFICATE REQUEST-----"};


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
    public void stepA_AddValidatorWithBlacklist() {
        validatorsHelper.openPage(getAdminWebUrl());
        validatorsHelper.addValidator(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepB_EditAValidator() {
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
        validatorsHelper.openEditValidatorPage(TestData.VALIDATOR_NAME);
        validatorsHelper.setBlackListSite(TestData.VALIDATOR_BLACKLIST_SITE);

        //Test to verify it returns a positive test result
        validatorsHelper.testBlacklistSite();
        validatorsHelper.assertBlackListResultsIsCorrect("Domain '" + TestData.VALIDATOR_BLACKLIST_SITE + "' is blacklisted. Matching domain on blacklist: 'evil.example.edu'");
    }


    @Test
    public void stepE_SaveValidatorSecondTime() {
        validatorsHelper.saveValidator();
        validatorsHelper.assertValidatorNameExists(TestData.VALIDATOR_NAME);
    }


    @Test
    public void stepF_AddCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.checkEnforceUniquePublicKeys(false);
        caHelper.checkEnforceUniqueDN(false);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.setOtherData(TestData.VALIDATOR_NAME);
    }

    @Test
    public void stepG_CreateCA() {
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }


    @Test
    public void stepH_AddCertificateProfile() {
        // Add Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void stepI_EditCertificateProfile() {
        // Edit certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);

        // Set validity
        certificateProfileHelper.fillValidity("720d");
    }

    @Test
    public void stepJ_SaveCertificateProfile() {
        // Save
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepK_AddEndEntityProfile() {
        eeProfileHelper.openPage(getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.ENTITY_NAME);
    }

    @Test
    public void stepL_EditEndEntityProfile() {
        eeProfileHelper.openEditEndEntityProfilePage(TestData.ENTITY_NAME);

        //Add DNS Name
        eeProfileHelper.setSubjectAlternativeName("DNS Name");
        
        //Add Certificate Profile
        eeProfileHelper.selectAvailableCp(TestData.CERTIFICATE_PROFILE_NAME);
        eeProfileHelper.selectDefaultCp(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void stepM_SaveEndEntityProfile() {
        eeProfileHelper.saveEndEntityProfile(true);
        eeProfileHelper.assertEndEntityProfileNameExists(TestData.ENTITY_NAME);
    }

    @Test
    public void stepN_MakeNewCertificate() {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
    }

    @Test
    public void stepO_SelectRequestTemplate() throws InterruptedException {
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.ENTITY_NAME);
        raWebHelper.selectCertificationAuthorityByName(TestData.CA_NAME);
        raWebHelper.selectKeyPairGenerationProvided();
    }

    @Test
    public void stepP_insertCsrCertificate() {
        raWebHelper.fillClearCsrText(StringUtils.join(TestData.CERTIFICATE_REQUEST_PEM, "\n"));
    }

    @Test
    public void stepQ_UploadCSRCertificate() {
        raWebHelper.clickUploadCsrButton();
    }

    @Test
    public void stepR_ProvideRequestInfo() throws InterruptedException {
        raWebHelper.fillMakeRequestEditCommonName("cn" + Calendar.getInstance().toString());
        raWebHelper.fillDnsName(TestData.VALIDATOR_BLACKLIST_SITE);
        TimeUnit.SECONDS.sleep(2);
    }

    @Test
    public void stepS_downloadPem() {
        raWebHelper.clickDownloadPem();
        raWebHelper.assertErrorMessageContains("No error message displayed when uploading using invalid domain",
                "Validation failed, certificate issuance aborted");
    }
}
