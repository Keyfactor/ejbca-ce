package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_DeleteCaAndAssertErrorMessages extends WebTestBase {

    //Classes
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static AdminRolesHelper adminRolesHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;

    // Test Data
    private static class TestData {
        static final String CA_NAME = "ECAQA-333-Ca";
        static final String CERTIFICATE_PROFILE_NAME = "ECAQA-333-1-CertificateProfile";
        static final String CA_MANAGEMENTCA = "ManagementCA";
        static final String ROLE_NAME = "ECAQA-333-Role";
        static final String END_ENTITY_PROFILE = "ECAQA-333-1-EndEntityProfile";
        static final String ROLE_TEMPLATE_AUDITOR = "Auditor";
        static final String AUTORIZED_CAS_ALL = "All";
        static final String AVAILABLE_CAS_ANY = "Any CA";
        static final List<String> LIST_OF_SELECTED_CAS = new ArrayList<>(Arrays.asList(CA_NAME, CA_MANAGEMENTCA));
        static final String EXPECTED_ALERT_MESSAGE = "Are you sure you want to delete the CA " + CA_NAME + "? "+
                "You should revoke the CA instead if you already have used it to issue certificates.";
        //ErrorMessages
        static final String ERROR_MESSAGE_ALL = "Couldn't delete CA, it's still used by some users or in the profiles or roles.";
        static final String ERROR_MESSAGE_CERTIFICATE_PROFILES = "CA is used in the following Certificate Profiles:";
        static final String ERROR_MESSAGE_ROLES = "CA is used in the following Roles:";
        static final String ERROR_MESSAGE_END_ENTITY = "CA is used in the following End Entity Profiles:";
        static final List<String> ERROR_DELETE_CA = new ArrayList<>();

    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        // Init helpers
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        adminRolesHelper = new AdminRolesHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);

    }

    @AfterClass
    public static void exit() {
        // super
        afterClass();

    }

    @After
    public void afterTest(){
        //Remove generated artifacts
        removeCaAndCryptoToken(TestData.CA_NAME);
        removeAdministratorRoleByName(TestData.ROLE_NAME);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        TestData.ERROR_DELETE_CA.clear();

    }

    @Before
    public void beforeTest(){
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);

    }
    
    // Tries to delete ca with only specific Ca chosen in Certificate Profile
    @Test
    public void testA_DeleteCaWithCertificateProfilesSpecific() {

        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.selectAvailableCa(TestData.CA_NAME);
        certificateProfileHelper.saveCertificateProfile();
        certificateProfileHelper.openPage(getAdminWebUrl());
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1, TestData.ERROR_MESSAGE_CERTIFICATE_PROFILES);
        TestData.ERROR_DELETE_CA.add(2,TestData.CERTIFICATE_PROFILE_NAME);
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }

    // Tries to delete Ca with two Cas chosen in Certificate Profile
    @Test
    public void testB_DeleteCaWithTwoCasChosenInCertificateProfile(){
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.selectMoreThanOneAvailableCa(TestData.LIST_OF_SELECTED_CAS);
        certificateProfileHelper.saveCertificateProfile();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1, TestData.ERROR_MESSAGE_CERTIFICATE_PROFILES);
        TestData.ERROR_DELETE_CA.add(2,TestData.CERTIFICATE_PROFILE_NAME);
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }


    // Deletes ca with "Any" Ca chosen in Certificate Profile
    @Test
    public void testC_DeleteCaWithCertificateProfilesAny() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.selectAvailableCa(TestData.AVAILABLE_CAS_ANY);
        certificateProfileHelper.saveCertificateProfile();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);

    }

    // Tries to delete ca with one ca chosen in endEntity
    @Test
    public void testD_DeleteCaWithEndEntityProfileSpecific() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.selectDefaultCa(TestData.CA_NAME);
        endEntityProfileHelper.selectAvailableCa(TestData.CA_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1, TestData.ERROR_MESSAGE_END_ENTITY);
        TestData.ERROR_DELETE_CA.add(2,TestData.END_ENTITY_PROFILE);
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }
    
    // Tries to delete Ca with two cas chosen in End Entity
    @Test
    public void testE_DeleteCaWithTwoChosenCasInEndEntityProfile(){
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1, TestData.ERROR_MESSAGE_END_ENTITY);
        TestData.ERROR_DELETE_CA.add(2,TestData.END_ENTITY_PROFILE);
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }
    
    //  Deletes Ca with "Any" ca chosen in End Entity
    @Test
    public void testF_DeleteCaWithEndEntityProfileAny(){
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE);
        endEntityProfileHelper.selectAvailableCa(TestData.AVAILABLE_CAS_ANY);
        endEntityProfileHelper.saveEndEntityProfile();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);

    }


    // Tries to delete ca with one specific Ca chosen in Role
    public void testG_DeleteCaWithRoleSpecific() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE_AUDITOR);
        adminRolesHelper.selectAvailableSingleCa(TestData.CA_NAME);
        adminRolesHelper.saveAccessRule();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1,TestData.ERROR_MESSAGE_ROLES);
        TestData.ERROR_DELETE_CA.add(2, TestData.ROLE_NAME );
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }

    // Tries to delete Ca with two cas chosen in Role
    @Test
    public void testH_DeleteCaWithTwoCasChosenInRole(){
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE_AUDITOR);
        adminRolesHelper.selectAvailableMultipleCa(TestData.LIST_OF_SELECTED_CAS);
        adminRolesHelper.saveAccessRule();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        TestData.ERROR_DELETE_CA.add(0, TestData.ERROR_MESSAGE_ALL);
        TestData.ERROR_DELETE_CA.add(1,TestData.ERROR_MESSAGE_ROLES);
        TestData.ERROR_DELETE_CA.add(2, TestData.ROLE_NAME);
        caHelper.assertHasErrorMessages(TestData.ERROR_DELETE_CA);
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertExists(TestData.CA_NAME);

    }

    // Deletes CA with "All" chosen in Role
    @Test
    public void testI_DeleteCaWithRoleAll() {
        adminRolesHelper.openPage(getAdminWebUrl());
        adminRolesHelper.addRole(TestData.ROLE_NAME);
        adminRolesHelper.openEditAccessRulesPage(TestData.ROLE_NAME);
        adminRolesHelper.selectRoleTemplate(TestData.ROLE_TEMPLATE_AUDITOR);
        adminRolesHelper.selectAvailableSingleCa(TestData.AUTORIZED_CAS_ALL);
        adminRolesHelper.saveAccessRule();
        //When
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCa(TestData.CA_NAME, true, TestData.EXPECTED_ALERT_MESSAGE);
        //Then
        caHelper.openPage(getAdminWebUrl());
        caHelper.assertNotExists(TestData.CA_NAME);

    }
}

