/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

import java.util.Collections;

/**
 * WebTest class for testing RA/Make New Request.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa161_MakeRequestRaWeb extends WebTestBase {

    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static CommandLineHelper commandLineHelper;

    //private static BaseHelper baseHelper;
    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "EcaQa161_EndEntity";
        private static final String END_ENTITY_NAME_PEM = "EcaQa161_pem";
        private static final String END_ENTITY_NAME_JKS = "EcaQa161_jks";
        private static final String END_ENTITY_NAME_PKCS12 = "EcaQa161_pkcs12";
        private static final String CA_NAME = "EcaQa161";
        private static final String SELECT_KEY_ALGORITHM = "RSA 2048 bits";
        private static final String CERTIFICATE_PROFILE_NAME = "EcaQa161_EndUser";
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
        afterClass();
    }

    /**
     * Method to clean up added entities by the defined test cases
     */
    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_PEM);
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_JKS);
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_PKCS12);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
        deleteDownloadedFile(TestData.END_ENTITY_NAME_PEM + ".pem");
        deleteDownloadedFile(TestData.END_ENTITY_NAME_JKS + ".jks");
        deleteDownloadedFile(TestData.END_ENTITY_NAME_PKCS12 + ".p12");
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
    public void stepD_MakePEMOnServerRequest() throws InterruptedException {
        makeRequest(TestData.END_ENTITY_NAME_PEM, raWebHelper::clickDownloadKeystorePem, ".pem");

        // Reset Make Request page
        raWebHelper.clickMakeRequestReset();
    }

    @Test
    public void stepE_MakeJKSOnServerRequest() throws InterruptedException {
        makeRequest(TestData.END_ENTITY_NAME_JKS, raWebHelper::clickDownloadJks, ".jks");
        
        // Click to reset Make Request page
        raWebHelper.clickMakeRequestReset();
    }

    @Test
    public void stepF_MakePKCS12OnServerRequest() throws InterruptedException {
        makeRequest(TestData.END_ENTITY_NAME_PKCS12, raWebHelper::clickDownloadPkcs12, ".p12");
    }
    
    // Makes Request based on Key Generation on Server on RA Web
    private void makeRequest(final String endEntityName, final Runnable clickDownloadButton, final String fileExtension) throws InterruptedException {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.selectKeyAlgorithm(TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute(0, endEntityName);
        raWebHelper.fillCredentials(endEntityName, "foo123");
        //Wait for screen update

        Thread.sleep(5000);
        clickDownloadButton.run();

        //Assert the existence of the downloaded certificate
        commandLineHelper.assertFileExists(getDownloadDir() + "/" + endEntityName + fileExtension);
    }

}