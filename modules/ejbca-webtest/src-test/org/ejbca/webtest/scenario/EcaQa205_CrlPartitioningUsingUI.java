package org.ejbca.webtest.scenario;

import org.apache.commons.lang.RandomStringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;
import java.math.BigInteger;
import java.util.*;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa205_CrlPartitioningUsingUI extends WebTestBase {

    private static WebDriver webDriver;
    List<String> listOfCertificates = new ArrayList<>();

    // Helpers
    private static CaHelper caHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper eeProfileHelper;
    private static RestCertificateHelper restCertificateHelper;
    private static CaStructureHelper caStructureHelper;
    private static QueryHelper queryHelper;
    private static ServicesHelper servicesHelper;
    private static AddEndEntityHelper addEndEntityHelperDefault;
    private static SwaggerUIHelper swaggerUIHelper;

    // Test Data
    private static class TestData {
        private static final String CA_NAME = "CrlPartitionCATest";
        private static final String CA_VALIDITY = "1y";
        private static final String CERTIFICATE_PROFILE_NAME = "CrlPartitionTestCertProfile";
        private static final String ENTITY_NAME = "EndEntityProfile";
        private static final String CRL_SERVICE = "ServiceCrlPartition";
        private static final String ISSUER_DN = "CN=" + CA_NAME;
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        eeProfileHelper = new EndEntityProfileHelper(webDriver);
        restCertificateHelper = new RestCertificateHelper(webDriver);
        caStructureHelper = new CaStructureHelper(webDriver);
        queryHelper = new QueryHelper(webDriver);
        servicesHelper = new ServicesHelper(webDriver);
        addEndEntityHelperDefault = new AddEndEntityHelper(webDriver);
        swaggerUIHelper = new SwaggerUIHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts

        removeCaAndCryptoToken(TestData.CA_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeEndEntityProfileByName(TestData.ENTITY_NAME);
        removeServiceByName(TestData.CRL_SERVICE);

        // super
        afterClass();
    }

    @Test
    public void stepA_GotoCertificateAuthorityPage() {
        //Verify CA using cryptotoken exists
        caHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void stepB_AddCA() {
        caHelper.addCa(TestData.CA_NAME);
    }


    @Test
    public void stepC_setValidity() {
        caHelper.setValidity(TestData.CA_VALIDITY);
    }


    @Test
    public void stepD_configureCRLPartitioning() {
        caHelper.checkIssuingDistPointOnCrls(true);
        caHelper.checkUseCrlPartitions(true);
        caHelper.setNumberOfPartitions("3");
        caHelper.setNumberOfRetiredPartitions("1");
    }

    @Test
    public void stepE_GenerateDefaultCrlDistributionPoint() {
        caHelper.clickGenerateDefaultCrlDistributionPoint();
        caHelper.assertDefaultCrlDistributionPointUri(
                getCrlUri()
                        + TestData.CA_NAME + "&partition=*");
    }

    @Test
    public void stepF_createCA() {
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);
    }

    @Test
    public void stepG_createCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void stepH_EditCertificateProfile() {
        // Edit certificate Profile
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);

        // Set validity
        certificateProfileHelper.fillValidity("360d");
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCrlDistributionPoints();
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPoint();

    }

    @Test
    public void stepI_SaveCertificateProfile() {
        // Save
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepJ_AddEndEntityProfile() {
        eeProfileHelper.openPage(this.getAdminWebUrl());
        eeProfileHelper.addEndEntityProfile(TestData.ENTITY_NAME);
    }

    @Test
    public void stepK_EditEntityProfile() {
        eeProfileHelper.openEditEndEntityProfilePage(TestData.ENTITY_NAME);
        eeProfileHelper.addSubjectAttribute("dn", "O, Organization");
        eeProfileHelper.addSubjectAttribute("dn",
                "ST, State or Province");
        eeProfileHelper.addSubjectAttribute("dn", "L, Locality");
        eeProfileHelper.addSubjectAttribute("dn", "C, Country (ISO 3166)");

        eeProfileHelper.setSubjectAlternativeName("DNS Name");
        eeProfileHelper.setSubjectAlternativeName("IP Address");

        eeProfileHelper.selectAvailableCp(TestData.CERTIFICATE_PROFILE_NAME);
        eeProfileHelper.selectDefaultCp(TestData.CERTIFICATE_PROFILE_NAME);
        eeProfileHelper.selectDefaultCa(TestData.CA_NAME);
        //Add DNS Name
        eeProfileHelper.setSubjectAlternativeName("DNS Name");
    }

    @Test
    public void stepL_SaveEntityProfile() {
        eeProfileHelper.saveEndEntityProfile(true);
    }

    //This next test serves as a utility to simply generate
    //a bulk of certificates and revoke them to use with
    //the CRL partitions

    @Test
    public void stepM_GenerateAndRevokeCertificates() throws InterruptedException {
        //Create 500 users.
        //Integer i = 0;
        //while (i <= 500) {

            //First add an end entity for the end user
            String username = "Crl" + RandomStringUtils.randomAlphanumeric(8);
            String password = "123" + RandomStringUtils.randomAlphanumeric(5);
            String endEntityName = "EcaQa205EE" + new Random().nextInt();

            Map<String, String> INPUT_END_ENTITY_FIELDMAP = new HashMap<>();
            {
                INPUT_END_ENTITY_FIELDMAP.put("Username", username);
                INPUT_END_ENTITY_FIELDMAP.put("Password (or Enrollment Code)", password);
                INPUT_END_ENTITY_FIELDMAP.put("Confirm Password", password);
                INPUT_END_ENTITY_FIELDMAP.put("CN, Common name", endEntityName);
            }

            System.out.println("User:  " + username);


            addEndEntityHelperDefault.openPage(getAdminWebUrl());
            addEndEntityHelperDefault.setEndEntityProfile(TestData.ENTITY_NAME);
            addEndEntityHelperDefault.fillFields(INPUT_END_ENTITY_FIELDMAP);
            addEndEntityHelperDefault.setCa(TestData.CA_NAME);
            addEndEntityHelperDefault.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
            addEndEntityHelperDefault.setToken("JKS file");
            addEndEntityHelperDefault.addEndEntity();

            //Open Swagger
            swaggerUIHelper.openPage(getSwaggerWebUrl());

            //First Generate a certificate for the user
            swaggerUIHelper.postEnrollKeystore();
            swaggerUIHelper.tryEnrollKeystore();
            swaggerUIHelper.setEnrollKeystoreAsJson(username, password, "RSA", "2048");
            swaggerUIHelper.executeEnrollKeystoreRequest();

            //Now verify the response
            if (swaggerUIHelper.assertEnrollKeystoreSuccess().contains("201")) {
                //Get the certificate serial number from downloaded file
                //This is commented out as the generated restcall response is not including
                //the certificate serial number as expected.

                //swaggerUIHelper.downloadEnrollKeystoreResponse();
                //String certificateSerialNumber =  swaggerUIHelper.getCertificateSerialNumber();
                //listOfCertificates.add(certificateSerialNumber);

                //**Wait a minute for the certificate to propagate in the system**
                Thread.sleep(30000);

                //Get the certificate serial number from database
                String certificateSerialNumber = queryHelper.getCertificateSerialNumberByUsername(getDatabaseConnection(),
                        "ejbca", username);

                //Convert to the hexidecimal format
                BigInteger hex = new BigInteger(certificateSerialNumber);
                String hexSerialNumber = hex.toString(16);
                listOfCertificates.add(hexSerialNumber);

                System.out.println("BigInteger Serial Number:  " + certificateSerialNumber);
                System.out.println("Hexidecimal Representative:  " + hexSerialNumber);

                //Revoke certificate
                swaggerUIHelper.putCertificateRevoke();
                swaggerUIHelper.tryCertificateRevoke();
                swaggerUIHelper.setCaSubjectDnForCertificateRevoke(TestData.ISSUER_DN);
                swaggerUIHelper.setCertificateSerialNumber(hexSerialNumber);
                swaggerUIHelper.setReasonToRevoke("UNSPECIFIED");
                swaggerUIHelper.setDateToRevoke();

                swaggerUIHelper.executeCertificateRevoke();

                if (!swaggerUIHelper.assertCertificateRevokeSuccess().contains("200")) {
                    swaggerUIHelper.downloadCertificateRevokeResponse();
                    System.out.println("Failed to revoke certificate serial:  " + " , Reason:  " +
                            swaggerUIHelper.getErrorMessage());
                }
            } else {
                System.out.println("Failed to enroll certificate:  " + " , Reason:  " +
                        swaggerUIHelper.getErrorMessage());

            }
         //   i++;
        //}
    }

    @Test
    public void stepN_CreateCRL() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(TestData.CA_NAME);
        caStructureHelper.assertCrlLinkWorks(TestData.CA_NAME);
    }

    @Test
    public void stepO_AssertCRLCounterInDBIsCorrect() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        queryHelper.assertCrlNumberIncreased(getDatabaseConnection(),
                "ejbca", TestData.CA_NAME);
    }


    @Test
    public void stepP_AssertCrlPartitionLinksInCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertDefaultCrlDistributionPointUri(getCrlUri()
                + TestData.CA_NAME + "&partition=*");
    }


    @Test
    public void stepQ_AssertCrlPartitionLinksInCertProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
    }



    @Test
    public void stepR_OpenServicePage() {
        servicesHelper.openPage(getAdminWebUrl());
    }

    @Test
    public void stepS_AddServices() {
        servicesHelper.addService(TestData.CRL_SERVICE);
    }

    @Test
    public void stepT_EditServices() {
        servicesHelper.openEditServicePage(TestData.CRL_SERVICE);
        servicesHelper.editService("CRL Updater");
        servicesHelper.setPeriod("1");
        servicesHelper.checkActive(true);
    }

    @Test(timeout = 65000)
    public void stepU_SaveService() {
        servicesHelper.saveService();
    }

    @Test
    public void stepV_AssertCrlCount() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(TestData.CA_NAME);
    }

    @Test
    public void stepX_RemoveCrlRowsFromDb() {
        queryHelper.removeDatabaseRowsByColumnCriteria(getDatabaseConnection(),
                "ejbca", "CRLData",
                "issuerDN='CN=" + TestData.CA_NAME + "'");
    }
}
