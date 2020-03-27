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

import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.*;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoAlertPresentException;
import org.openqa.selenium.WebDriver;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

/**
 * WebTest class for testing RA/Make New Request.
 *
 * @version $Id: EcaQa161_MakeServerRequestsOnRaWeb.java 32247 2020-03-36 09:19:46Z margarett $
 *
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa161_MakeServerRequestsOnRaWeb {

    private static WebDriver webDriver;

    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    private static CommandLineHelper commandLineHelper;

    //private static BaseHelper baseHelper;
    public static class TestData {
        private static final String END_ENTITY_PROFILE_NAME = "EcaQa161_EndEntity";
        private static final String END_ENTITY_NAME = "EcaQa161_TestEndEntity";
        private static final String CA_NAME = "EcaQa161";
        private static final String SELECT_KEY_ALGORITHM = "RSA 2048 bits";
        private static final String CERTIFICATE_PROFILE_NAME = "EcaQa161_EndUser";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        caHelper = new CaHelper(webDriver);
        commandLineHelper = new CommandLineHelper();
        cleanup();
    }

    @AfterClass
    public static void exit(){
        cleanup();
    }

    /**
     * Method to clean up added entities by the defined test cases
     */
    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_NAME);
        removeEndEntityProfileByName(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_PROFILE_NAME);
        removeCertificateProfileByName(EcaQa161_MakeRequestRaWeb.TestData.CERTIFICATE_PROFILE_NAME);
        removeCaAndCryptoToken(EcaQa161_MakeRequestRaWeb.TestData.CA_NAME);
    }

    @Test
    public void stepA_CreateCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(EcaQa161_MakeRequestRaWeb.TestData.CA_NAME);
        caHelper.setValidity("1y");
        caHelper.createCa();
    }

    @Test
    public void stepB_CreateCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(EcaQa161_MakeRequestRaWeb.TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(EcaQa161_MakeRequestRaWeb.TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepC_CreateEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void stepD_MakePEMOnServerRequest() throws InterruptedException {
        String endEntity =  "Pem";

        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectCertificationAuthorityByName(EcaQa161_MakeRequestRaWeb.TestData.CA_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.selectKeyAlgorithm(EcaQa161_MakeRequestRaWeb.TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute0(endEntity);
        raWebHelper.fillCredentials(endEntity, "foo123");
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.clickDownloadKeystorePem();

        //Assert the existence of the downloaded certificate
        commandLineHelper.assertFileExists("/tmp/" + endEntity + ".pem");

        //Reset Make Request page
        raWebHelper.clickMakeRequestReset();
    }

    @Test
    public void stepE_MakeJKSOnServerRequest() throws InterruptedException {
        String endEntity =  "Jks";

        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectCertificationAuthorityByName(EcaQa161_MakeRequestRaWeb.TestData.CA_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.selectKeyAlgorithm(EcaQa161_MakeRequestRaWeb.TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute0(endEntity);
        raWebHelper.fillCredentials(endEntity, "foo123");
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.clickDownloadJks();

        //Assert the existence of the downloaded certificate
        commandLineHelper.assertFileExists("/tmp/" + endEntity + ".jks");

        //Click to reset Make Request page
        raWebHelper.clickMakeRequestReset();
    }


    @Test
    public void stepF_MakePKCS12OnServerRequest() throws InterruptedException {
        String endEntity =  "Pkcs123";

        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(EcaQa161_MakeRequestRaWeb.TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectCertificationAuthorityByName(EcaQa161_MakeRequestRaWeb.TestData.CA_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        //Wait for screen update
        Thread.sleep(5000);
        raWebHelper.selectKeyAlgorithm(EcaQa161_MakeRequestRaWeb.TestData.SELECT_KEY_ALGORITHM);
        //Wait for screen update
        Thread.sleep(5000);
        //Enter common name
        raWebHelper.fillDnAttribute0(endEntity);
        raWebHelper.fillCredentials(endEntity, "foo123");
        //Wait for screen update

        //** Still seeking solution to force Firefox to download PKCS12 **
        //Thread.sleep(5000);
        //raWebHelper.clickDownloadPkcs12();

        //Assert the existence of the downloaded certificate
        //commandLineHelper.assertFileExists("/tmp/" + endEntity + ".p12");
    }
}
