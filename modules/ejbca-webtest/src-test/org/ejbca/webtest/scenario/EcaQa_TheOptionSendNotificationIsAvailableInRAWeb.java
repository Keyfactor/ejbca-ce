package org.ejbca.webtest.scenario;


import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.scenario.EcaQa161_MakeRequestRaWeb.TestData;
import org.ejbca.webtest.util.TestFileResource;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Arrays;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_TheOptionSendNotificationIsAvailableInRAWeb extends WebTestBase {
    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static CommandLineHelper commandLineHelper;
    private static EndEntityProfileHelper eeProfileHelper;

    //private static BaseHelper baseHelper;
    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "Notification_EndEntity";
        //private static final String END_ENTITY_NAME_PEM = "Notifacation_pem";
        //private static final String END_ENTITY_NAME_JKS = "Notifacation_jks";
        private static final String END_ENTITY_NAME_PKCS12 = "Notifacation_pkcs12";
        private static final String CA_NAME = "Notifacation_CA";
        private static final String COMMON_NAME = "CommomName";
        private static final String USER_NAME = "UserName"; 
        private static final String ENROLLMENT_CODE = "foo123";
        private static final String SELECT_KEY_ALGORITHM = "RSA 2048 bits";
        private static final String CERTIFICATE_PROFILE_NAME = "Notifacation_EndUser";
        private static final int NOTIFICATION_INDEX = 0;
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        raWebHelper = new RaWebHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        commandLineHelper = new CommandLineHelper();
        cleanup();
    }

    @AfterClass
    public static void exit(){
        cleanup();
        //super
        afterClass();
    }

    /**
     * Method to clean up added entities by the defined test cases
     */
    private static void cleanup() {
        // Remove generated artifacts       
        removeEndEntityByUsername(TestData.USER_NAME);       
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeCertificateByUsername(TestData.USER_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
        deleteDownloadedFile(TestData.COMMON_NAME + ".pem");
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
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepC_CreateEndEntityProfile() throws InterruptedException {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.editEndEntityProfile(
            TestData.CERTIFICATE_PROFILE_NAME,
            Arrays.asList(TestData.CERTIFICATE_PROFILE_NAME),
            TestData.CA_NAME,
            Arrays.asList(TestData.CA_NAME)            
        );
        endEntityProfileHelper.triggerSendNotification();
        Thread.sleep(3000); 
        endEntityProfileHelper.addNotification();
        Thread.sleep(3000); 
        endEntityProfileHelper.setNotificationSender(TestData.NOTIFICATION_INDEX, "test@mail.primekey.test");
        endEntityProfileHelper.setNotificationRecipiet(TestData.NOTIFICATION_INDEX, "mailtest@mail.primekey.test");
        endEntityProfileHelper.setNotificationSubject(TestData.NOTIFICATION_INDEX,"test subject");
        endEntityProfileHelper.setNotificationMessage(TestData.NOTIFICATION_INDEX, "test message");
        Thread.sleep(3000); 
        
        endEntityProfileHelper.saveEndEntityProfile();
    }
    
    @Test
    public void stepD_NotifiacationIsAvalible() throws InterruptedException {
     // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);        
        //Select KeyPairGeneration Provided by CA
        raWebHelper.selectKeyPairGenerationPostpone();
        Thread.sleep(3000); 
        //raWebHelper.selectKeyAlgorithm(TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
       // Thread.sleep(2000);
        
        
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME);
        Thread.sleep(1000);        
        raWebHelper.fillCredentials(TestData.USER_NAME, TestData.ENROLLMENT_CODE);        
        Thread.sleep(1000);
        raWebHelper.clickDownloadKeystorePem();
        Thread.sleep(3000); 

        
    }
    /*@Test org.ejbca.core.ejb.ra.EndEntityManagementSessionBean
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
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME_1);        
        raWebHelper.fillUsernameProvodeUserCredentials(TestData.USER_NAME_1); 
        //Download PEM
        raWebHelper.clickDownloadPem();      
        Thread.sleep(2000);
        raWebHelper.assertDownloadedFileExits(getDownloadDir() + "/" + TestData.COMMON_NAME_1 + ".pem");
       }
     * 
     */

}
