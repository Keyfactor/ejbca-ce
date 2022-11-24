package org.ejbca.webtest.scenario;

import java.util.Collections;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.util.TestFileResource;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * This test verifies that restrictions in the certificate profile is applied for
 * enrollments through the RA web, using Provide by User and CSR enrollments in DER, CSR format.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECA-10582">ECA-10582</a>
 * 
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_MakeRequestUsingCSRDER extends WebTestBase {
    
    //Helpers
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static RaWebHelper raWebHelper;
       
    //Test Data
    public static class TestData {
        static final String CERTIFICATE_PROFILE_NAME = "RestrictCP";
        static final String CERTIFICATE_PROFILE_KEY_ALGORITHM = "RSA";
        static final String CERTIFICATE_PROFILE_KEY_BIT_LENGTH = "2048 bits";
        static final String END_ENTITY_PROFILE_NAME = "RestrictEEP";
        static final String END_ENTITY_PROFILE_COUNTRY_FIELD = "C, Country (ISO 3166)";
        static final String END_ENTITY_PROFILE_ORGANIZATION_FIELD = "O, Organization";

        static final String CA_TYPE = "ManagementCA";
        static final String COMMON_NAME = "ComonName";
        static final String USER_NAME = "UserName";
        static final String COMMON_NAME_1 = "CommonName1";
        static final String USER_NAME_1 = "UserName1";
        static final String COMMON_NAME_FROM_CSR = "Restrict_CN";
        static final String COUNTRY = "US";
        static final String ORGANIZATION = "Primekey webTest Inc";
        static final String CERTIFICATE_REQUEST_CSR = "Restrict_CN.csr";
        static final String CERTIFICATE_REQUEST_CSR_WITH_NEW_KEYWORD_IN_HEADER = "Restrict_CN_NEW.csr";
        static final String CERTIFICATE_REQUEST_DER = "Restrict_CN.der"; 
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
        removeEndEntityByUsername(TestData.USER_NAME);
        removeCertificateByUsername(TestData.USER_NAME);
        removeEndEntityByUsername(TestData.USER_NAME_1);
        removeCertificateByUsername(TestData.USER_NAME_1);
        deleteDownloadedFile(TestData.COMMON_NAME + ".pem");
        deleteDownloadedFile(TestData.COMMON_NAME_1 + ".pem");
        
        // super
        afterClass();
    }
    
    public void cleanUp() {
        removeEndEntityByUsername(TestData.USER_NAME);
        removeCertificateByUsername(TestData.USER_NAME);
        raWebHelper.clickMakeRequestReset();
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
        endEntityProfileHelper.setSubjectDNName(TestData.END_ENTITY_PROFILE_COUNTRY_FIELD);
        endEntityProfileHelper.setSubjectDNName(TestData.END_ENTITY_PROFILE_ORGANIZATION_FIELD);
        endEntityProfileHelper.saveEndEntityProfile();
    }  
        
    @Test
    public void stepC_MakeRequestUsingDER() throws InterruptedException {
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);        
        //Select KeyPairGeneration Provided by user
        raWebHelper.selectKeyPairGenerationProvided();
        Thread.sleep(3000);        
        //Upload RestrictCN.der
        raWebHelper.fillCsrFilename(new TestFileResource(TestData.CERTIFICATE_REQUEST_DER).getFileAbsolutePath());             
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME);     
        raWebHelper.fillUsernameProvideUserCredentials(TestData.USER_NAME);
        //Download PEM
        raWebHelper.clickDownloadPem();    
        Thread.sleep(2000);        
        raWebHelper.assertDownloadedFileExits(getDownloadDir() + "/" + TestData.COMMON_NAME + ".pem");                             
    }
   
    @Test
    public void stepD_MakeRequestUsingCSR() throws InterruptedException {
        cleanUp();
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);        
        //Select KeyPairGeneration Provided by user
        raWebHelper.selectKeyPairGenerationProvided();
        Thread.sleep(3000);        
        //Upload RestrictCN.der
        raWebHelper.fillCsrFilename(new TestFileResource(TestData.CERTIFICATE_REQUEST_CSR).getFileAbsolutePath());
        raWebHelper.verifyCommonNameValue(TestData.COMMON_NAME_FROM_CSR,"Common name value was not parsed from csr");
        raWebHelper.verifyCountryValue(TestData.COUNTRY,"Country value was not parsed from csr");
        raWebHelper.verifyOrganizationValue(TestData.ORGANIZATION,"Organization value was not parsed from csr");
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME_1);
        raWebHelper.fillUsernameProvideUserCredentials(TestData.USER_NAME_1);

        //Download PEM
        raWebHelper.clickDownloadPem();      
        Thread.sleep(2000);
        raWebHelper.assertDownloadedFileExits(getDownloadDir() + "/" + TestData.COMMON_NAME_1 + ".pem");
       }
    
    @Test
    public void stepE_MakeRequestUsingCSRNewKeyword() throws InterruptedException {
        cleanUp();
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);        
        //Select KeyPairGeneration Provided by user
        raWebHelper.selectKeyPairGenerationProvided();
        Thread.sleep(3000);        
        //Upload RestrictCN.der
        raWebHelper.fillCsrFilename(new TestFileResource(
                TestData.CERTIFICATE_REQUEST_CSR_WITH_NEW_KEYWORD_IN_HEADER).getFileAbsolutePath());
        raWebHelper.verifyCommonNameValue(TestData.COMMON_NAME_FROM_CSR,"Common name value was not parsed from csr");
        raWebHelper.verifyCountryValue(TestData.COUNTRY,"Country value was not parsed from csr");
        raWebHelper.verifyOrganizationValue(TestData.ORGANIZATION,"Organization value was not parsed from csr");
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME_1);
        raWebHelper.fillUsernameProvideUserCredentials(TestData.USER_NAME_1);
      
       }
}
