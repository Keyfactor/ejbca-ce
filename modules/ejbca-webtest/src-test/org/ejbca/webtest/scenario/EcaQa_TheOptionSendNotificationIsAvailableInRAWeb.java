package org.ejbca.webtest.scenario;


import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.utils.RandomNumber;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;
import static org.junit.Assert.assertEquals;
import java.util.Arrays;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_TheOptionSendNotificationIsAvailableInRAWeb extends WebTestBase {
    
    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static MailHelper mailHelper; 
    private static RandomNumber randomNumber;    
    
   
    //private static BaseHelper baseHelper;
    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "Notification_EndEntity";        
        private static final String CA_NAME = "Notifacation_CA";
        private static final String COMMON_NAME = "CommomName";
        private static final String USER_NAME = "UserName"; 
        private static final String ENROLLMENT_CODE = "foo123";
        private static final String SELECT_KEY_ALGORITHM = "RSA 2048 bits";
        private static final String CERTIFICATE_PROFILE_NAME = "Notifacation_EndUser";
        private static final int NOTIFICATION_INDEX = 0;
        private static final String EMAIL_SENDER = "test@mail.primekey.test";
        private static final String EMAIL_RECIPIENT = "mailtest@mail.primekey.test";
        private static final String EMAIL_SUBJECT = "TestSubject_"+ randomNumber.generateNumbers(100);
        private static final String EMAIL_MESSAGE = "Test message";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        raWebHelper = new RaWebHelper(webDriver);
        mailHelper = new MailHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        randomNumber = new RandomNumber();             
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
        endEntityProfileHelper.setNotificationSender(TestData.NOTIFICATION_INDEX,TestData.EMAIL_SENDER );
        endEntityProfileHelper.setNotificationRecipient(TestData.NOTIFICATION_INDEX,TestData.EMAIL_RECIPIENT );
        endEntityProfileHelper.setNotificationSubject(TestData.NOTIFICATION_INDEX,TestData.EMAIL_SUBJECT);
        endEntityProfileHelper.setNotificationMessage(TestData.NOTIFICATION_INDEX,TestData.EMAIL_MESSAGE );
        Thread.sleep(3000); 
        
        endEntityProfileHelper.saveEndEntityProfile();
    }
    
    @Test
    public void stepD_NotificationIsAvalible() throws InterruptedException {
     // Go to RA Web -> Make New Request
        raWebHelper.openPage(getRaWebUrl());
        Thread.sleep(2000);
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);        
        //Select KeyPairGeneration Provided by CA
        raWebHelper.selectKeyPairGenerationOnServer();
        Thread.sleep(3000); 
        raWebHelper.selectKeyAlgorithm(TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
        Thread.sleep(2000);     
        raWebHelper.fillRequiredSubjectDNAttributes(TestData.COMMON_NAME);
        Thread.sleep(1000);        
        raWebHelper.fillCredentials(TestData.USER_NAME, TestData.ENROLLMENT_CODE);
        raWebHelper.fillCredentialEmail(TestData.EMAIL_RECIPIENT);
        Thread.sleep(1000);
        raWebHelper.clickDownloadKeystorePem();
        Thread.sleep(2000);
        
        //Open page to email-server 
        mailHelper.openPage();    
        Thread.sleep(2000);       
        assertEquals( mailHelper.getEmailLastSubject(), TestData.EMAIL_SUBJECT );        
    }    
}
