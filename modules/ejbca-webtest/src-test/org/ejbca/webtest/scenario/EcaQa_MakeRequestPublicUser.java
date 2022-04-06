package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AdminRolesHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.ejbca.webtest.utils.ConfigurationConstants;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Collections;

/**
 * WebTest class for testing RA/Make New Request with public access user.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_MakeRequestPublicUser extends WebTestBase {


    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static AdminRolesHelper adminRolesHelperDefault;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static CommandLineHelper commandLineHelper;

    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "EcaRaPublicUser_EEP";
        private static final String CA_NAME = "EcaRaPublicUser_CA";
        private static final String CERTIFICATE_PROFILE_NAME = "EcaRaPublicUser_CP";
        private static final String END_ENTITY_NAME = "EcaRaPublicUser_EE";
        private static final String ROLE_NAME = "EcaRaPublicUser_Role";
        private static final String MATCH_WITH = "PublicAccessAuthenticationToken: Any transport (HTTP or HTTPS)";
        static final String CERTIFICATE_PROFILE_KEY_ALGORITHM = "RSA";
        static final String CERTIFICATE_PROFILE_KEY_BIT_LENGTH = "2048 bits";
        private static final String SELECT_KEY_ALGORITHM = "RSA 2048 bits";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, ConfigurationConstants.PROFILE_FIREFOX_DEFAULT);
        final WebDriver webDriverDefault = getLastWebDriver();
        certificateProfileHelper = new CertificateProfileHelper(webDriverDefault);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriverDefault);
        caHelper = new CaHelper(webDriverDefault);
        adminRolesHelperDefault = new AdminRolesHelper(webDriverDefault);
        beforeClass(false, null);
        final WebDriver webDriverPublic = getLastWebDriver();
        raWebHelper = new RaWebHelper(webDriverPublic);
        commandLineHelper = new CommandLineHelper();
        cleanup();
    }

    @AfterClass
    public static void exit() {
        cleanup();
        afterClass();
    }

    /**
     * Method to clean up added entities by the defined test cases
     */
    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        //delete role
    }

    @Test
    public void stepA_CreateCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.createCa();
    }

    @Test
    public void stepB_CreateCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.editCertificateProfile(
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_KEY_ALGORITHM),
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_KEY_BIT_LENGTH)
        );
        certificateProfileHelper.selectAvailableCa(TestData.CA_NAME);
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepC_CreateEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.editEndEntityProfile(
                TestData.CERTIFICATE_PROFILE_NAME,
                Collections.singletonList(TestData.CERTIFICATE_PROFILE_NAME),
                TestData.CA_NAME,
                Collections.singletonList(TestData.CA_NAME)
        );
        endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepD_CreatePublicAccessRole() {
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.addRole(TestData.ROLE_NAME);
        // Add access rules
        adminRolesHelperDefault.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.switchViewModeFromBasicToAdvanced();
        adminRolesHelperDefault.setRuleCheckedRadioButton("/ca_functionality/create_certificate/", "ALLOW");
        adminRolesHelperDefault.setRuleCheckedRadioButton("/ra_functionality/create_end_entity/", "ALLOW");
        adminRolesHelperDefault.setRuleCheckedRadioButton("/endentityprofilesrules/", "ALLOW");
        adminRolesHelperDefault.setRuleCheckedRadioButton("/ca/" + TestData.CA_NAME + "/", "ALLOW");
        adminRolesHelperDefault.saveAccessRule();

        // Add member
        adminRolesHelperDefault.openPage(getAdminWebUrl());
        adminRolesHelperDefault.openEditMembersPage(TestData.ROLE_NAME);
        adminRolesHelperDefault.selectMatchWith(TestData.MATCH_WITH);
        adminRolesHelperDefault.clickAddMember();
    }

    @Test
    public void stepF_openRAAsPublicUser() throws InterruptedException {
        raWebHelper.openPage(getRaWebPublicUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute(0, TestData.END_ENTITY_NAME);
        raWebHelper.fillCredentials(TestData.END_ENTITY_NAME, "foo123");
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.clickDownloadPkcs12();

        //Assert the existence of the downloaded certificate
        commandLineHelper.assertFileExists(getDownloadDir() + "/" + TestData.END_ENTITY_NAME + ".p12");
    }

}
