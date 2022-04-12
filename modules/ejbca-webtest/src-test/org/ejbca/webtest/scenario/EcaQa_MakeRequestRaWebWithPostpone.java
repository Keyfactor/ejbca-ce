package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Collections;

/**
 * WebTest class for testing RA/Make New Request Postpone option.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa_MakeRequestRaWebWithPostpone extends WebTestBase {

    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;

    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "EcaRaPostpone_EndEntity";
        private static final String CA_NAME = "EcaRaPostpone_CA";
        private static final String CERTIFICATE_PROFILE_NAME = "EcaRaPostpone_CP";
        private static final String END_ENTITY_NAME = "EcaRaPostpone_EE_name";
        private static final String SELECT_TOKEN_TYPE = "PKCS#12 keystore (P12 or PFX)";
        private static final String SUCCESS_MESSAGE = "End Entity with username '" + END_ENTITY_NAME + "' has been added successfully";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        raWebHelper = new RaWebHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        caHelper = new CaHelper(webDriver);
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
    public void stepD_MakePostponeServerRequest() throws InterruptedException {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationPostpone();
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.assertTokenTypeSelection(true);
        raWebHelper.selectTokenType(TestData.SELECT_TOKEN_TYPE);
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute(0, TestData.END_ENTITY_NAME);
        raWebHelper.fillCredentials(TestData.END_ENTITY_NAME, "foo123");
        raWebHelper.clickAddEndEntity();
        Thread.sleep(5000);
        raWebHelper.assertInfoMessageContains("No info message displayed when adding end entity", TestData.SUCCESS_MESSAGE);
    }

    @Test
    public void stepE_SearchEndEntity() throws InterruptedException {
        raWebHelper.clickSearchEndEntities(getRaWebUrl()) ;
        raWebHelper.fillSearchEndEntity(TestData.END_ENTITY_NAME);
        raWebHelper.assertSearchTableResult(1);
    }
}
