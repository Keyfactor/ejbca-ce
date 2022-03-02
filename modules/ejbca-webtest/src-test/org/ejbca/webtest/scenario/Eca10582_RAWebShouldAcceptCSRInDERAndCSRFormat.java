package org.ejbca.webtest.scenario;

import java.util.Collections;

import org.apache.commons.lang.StringUtils;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.scenario.EcaQa125_RaCpRestrictions.TestData;
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
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Eca10582_RAWebShouldAcceptCSRInDERAndCSRFormat extends WebTestBase {
    
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
        static final String CA_TYPE = "ManagementCA";
        static final String COMMON_NAME = "RestrictCN1";
        static final String USER_NAME = "User1";
        static final String CERTIFICATE_REQUEST_CSR = "/resources-test/RestrictCN.csr";
        static final String CERTIFICATE_REQUEST_DER = "RestrictCN.der";
//        static final String CERTIFICATE_REQUEST_DER = "/home/nutcha/ejbca/modules/ejbca-webtest/resources-test/RestrictCN.der";
        
                
    }
    
    //getClass().getResource(TestData.CERTIFICATE_REQUEST_DER).getFile();
    
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
    public void stepC_KeyPairViaCSR() throws InterruptedException {
        // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        
        //Select KeyPairGeneration Provided by user
        raWebHelper.selectKeyPairGenerationProvided();
        Thread.sleep(3000);
//        raWebHelper.fillCsrFilename(getClass().getResource(TestData.CERTIFICATE_REQUEST_DER).getFile());
        raWebHelper.fillCsrFilename(new TestFileResource(TestData.CERTIFICATE_REQUEST_DER).getFileAbsolutePath());
//        raWebHelper.fillCsrFilename(TestData.CERTIFICATE_REQUEST_DER);
//        raWebHelper.clickUploadCsrButton();
        Thread.sleep(2000);
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME);
        Thread.sleep(2000);
        raWebHelper.fillUsernameProvodeUserCredentials(TestData.USER_NAME);
        
        
        //Download PEM
        raWebHelper.clickDownloadPem();      
            
        
    }
    

}
