package org.ejbca.webtest.scenario;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.util.HashMap;
import java.util.Set;

import org.cesecore.util.CertTools;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CaStructureHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.firefox.FirefoxProfile;
import org.openqa.selenium.interactions.Actions;
import org.junit.Assert.*;




@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa219_RevokeEndEntityCertificate extends WebTestBase {
    //Classes used.
    private static WebDriver webDriver;
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    private static CaHelper caHelper;
    private static RaWebHelper raWebHelper;
    private static CaStructureHelper caStructureHelper;
    
    //String variables.
    private static final String END_ENTITY_NAME = "ECAQA71EE";
    private static final String END_ENTITY_PASSWORD = "foo123";
    private static final String END_ENTITY_COMMON_NAME = "ECAQA71EE";
    private static final String END_ENTITY_CA = "ManagementCA";

    private static final String CA_NAME = "ECAQA71CA";
    private static final String CERTIFICATE_PROFILE_NAME = "ENDUSER";
    private static final String CA_VALIDITY = "15y";
    
    private static final By ENROLL_XPATH = By.xpath("//*[@id='enrollment']");
    private static final By USE_USERNAME_XPATH = By.xpath("//a[@href='enrollwithusername.xhtml']");
    private static final By USERNAME_INPUTFIELD_ID = By.id("enrollWithUsernameForm:username");
    private static final By ENROLLMENT_CODE_TEXTFIELD_ID = By.id("enrollWithUsernameForm:enrollmentCode");
    private static final By CHECKBOX_ID = By.id("enrollWithUsernameForm:checkButton");
    private static final By DOWNLOAD_PKCS12 = By.id("enrollWithUsernameForm:generatePkcs12");
    private static final By SEARCH_END_ENTITIES_WITH_STATUS_HAMBURGERLIST_XPATH = By.xpath("//select[@name='selectliststatus']");
    private static final By SEARCH_END_ENTITIES_WITH_STATUS_ALL_XPATH = By.xpath("//select[@name='selectliststatus']/option[2]");
    private static final By REVOKE_SELECTED_BUTTON_XPATH = By.xpath("//input[@name='buttonrevokeusers']");
    private static final By CERTIFICATE_SERIAL_NUMBER_XPATH = By.xpath("//*[@id='contentBlock']//label[contains(text(),'Certificate Serial Number')]/../following-sibling::td/label");

    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(END_ENTITY_NAME);
        removeCertificateProfileByName(CERTIFICATE_PROFILE_NAME);
        removeCaByName(CA_NAME);
        removeCryptoTokenByCaName(CA_NAME);
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        caHelper = new CaHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
        caStructureHelper = new CaStructureHelper(webDriver);

    }

    @AfterClass
    public static void exit() {
        cleanup();
        afterClass();
    }
    
    
    @Test
    public void testA_addCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(CA_NAME);
        // Set validity (required)
        caHelper.setValidity(CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(CA_NAME);
    }

    @Test
    public void testB_AddEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", END_ENTITY_PASSWORD);
        fields.put("Confirm Password", END_ENTITY_PASSWORD);
        fields.put("CN, Common name", END_ENTITY_COMMON_NAME);
        addEndEntityHelper.setToken("P12 file");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile(CERTIFICATE_PROFILE_NAME);
        addEndEntityHelper.setCa(END_ENTITY_CA);
        addEndEntityHelper.addEndEntity();
    }

    @Test
    public void testC_RaWebSaveP12() {
        raWebHelper.openPage(getRaWebUrl());
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        //Clicks trough to Enroll with Use Username
        Actions action = new Actions(getWebDriver());
        WebElement element = webDriver.findElement(ENROLL_XPATH);
        action.moveToElement(element).moveToElement(webDriver.findElement(USE_USERNAME_XPATH)).click().build().perform();
        WebElement usernameElement = webDriver.findElement(USERNAME_INPUTFIELD_ID);
        usernameElement.sendKeys(END_ENTITY_NAME);
        WebElement enrollmentCodeElement = webDriver.findElement(ENROLLMENT_CODE_TEXTFIELD_ID);
        enrollmentCodeElement.sendKeys(END_ENTITY_PASSWORD);
        WebElement checkBoxElement = webDriver.findElement(CHECKBOX_ID);
        checkBoxElement.click();
        WebElement downloadP12BoxElement = webDriver.findElement(DOWNLOAD_PKCS12);
        downloadP12BoxElement.click();

    }

    @Test
    public void testD_SearchEndEntities() {
        String mainWindow = webDriver.getWindowHandle();
        getStringFromSearchEndEntities();
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        webDriver.close();
        webDriver.switchTo().window(mainWindow);
    }
    
    @Test
    public void testE_DownloadCrl() {
        caStructureHelper.openCrlPage(getAdminWebUrl());
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        caStructureHelper.clickCrlLinkAndAssertNumberIncreased(CA_NAME);
        caStructureHelper.assertCrlLinkWorks(CA_NAME);
        caStructureHelper.openCrlPage(getAdminWebUrl());
        try {
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        caStructureHelper.downloadCrl(CA_NAME);
       
    }
    
    @Test
    public void testF_compareSerialNumber() throws CRLException {
        final File file = new File("/tmp/"+ CA_NAME +".crl");
        byte[] crlData = null;
            try {
                crlData = getFileFromDisk(file);
            } catch (IOException e) {
                e.printStackTrace();
                //log.error("File '" + filename + "' could not be read.");
            }
            
       X509CRL crl = CertTools.getCRLfromByteArray(crlData);
       Set<? extends X509CRLEntry> crlEntries = crl.getRevokedCertificates();
       if(crlEntries != null) {
           for(X509CRLEntry crlEntry : crlEntries) {
               BigInteger serial = crlEntry.getSerialNumber();
               String serialNumber = serial.toString();
               assertEquals(serialNumber, getStringFromSearchEndEntities());
           }
       }
    }
    
    private String getStringFromSearchEndEntities() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        //Revokes the end entity
        WebElement hamburgerList = webDriver.findElement(SEARCH_END_ENTITIES_WITH_STATUS_HAMBURGERLIST_XPATH);
        WebElement allElementInHamburgerList = webDriver.findElement(SEARCH_END_ENTITIES_WITH_STATUS_ALL_XPATH);
        hamburgerList.click();
        allElementInHamburgerList.click();
        searchEndEntitiesHelper.fillSearchCriteria(END_ENTITY_NAME, null, null, null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.triggerSearchResultFirstRowSelect();
        WebElement revokeButton = webDriver.findElement(REVOKE_SELECTED_BUTTON_XPATH);
        revokeButton.click();

        //Handles the CertificateView Popup-window.
        Alert alert = webDriver.switchTo().alert();
        alert.accept();
        String mainWindow = webDriver.getWindowHandle();
        try {
            Thread.sleep(4000);
            searchEndEntitiesHelper.clickViewCertificateForRow(END_ENTITY_COMMON_NAME);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        for (String windowHandle : webDriver.getWindowHandles()) {
            webDriver.switchTo().window(windowHandle);
        }
        
        WebElement certificateSerialNumberElement = webDriver.findElement(CERTIFICATE_SERIAL_NUMBER_XPATH);
        return certificateSerialNumberElement.getText();
    }
    
    private byte[] getFileFromDisk(final File file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        while ((bytes = fileInputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, bytes);
        }
        fileInputStream.close();
        return baos.toByteArray();
    }
    

    
}
