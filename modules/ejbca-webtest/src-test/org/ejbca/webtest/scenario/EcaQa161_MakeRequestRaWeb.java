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
import org.ejbca.webtest.helper.AddEndEntityHelper;
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

// TODO JavaDoc
/**
 * Selenium WebTesst class for EJBCAQA-161.
 *
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa161_MakeRequestRaWeb extends WebTestBase {

    private static WebDriver webDriver;

    //helpers
    private static RaWebHelper raWebHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CaHelper caHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static AddEndEntityHelper addEndEntityHelper;

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
        // cleanup();
    }

    @AfterClass
    public static void exit(){
        cleanup();
    }

    /**
     * Method intended to clean up artifacts post testing.
     */
    private static void cleanup() {
        // Remove generated artifacts
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeCaAndCryptoToken(TestData.CA_NAME);
    }

    @Test
    public void stepA_CreateCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.saveCertificateProfile();
    }

    @Test
    public void stepB_CreateEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        //endEntityProfileHelper.editEndEntityProfile();
        //endEntityProfileHelper.saveEndEntityProfile();
    }

    @Test
    public void stepC_CreateCA() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.createCa();
    }

    /*
    @Test
    public void stepD_AddEndEntity(){                       THIS STEP IS REDUNDANT SINCE RA WEB DOES THE SAME THING
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<>();

        fields.put("Username", TestData.END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", TestData.END_ENTITY_NAME);
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCertificateProfile("ENDUSER");
        addEndEntityHelper.setCa(getCaName());
        addEndEntityHelper.addEndEntity();

    }
    */

    @Test
    public void stepE_MakeRequest() throws InterruptedException {
        raWebHelper.openPage(getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.END_ENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationOnServer();
        raWebHelper.selectKeyAlgorithm(TestData.SELECT_KEY_ALGORITHM);
        raWebHelper.fillMakeRequestEditCommonName("EcaQa161_TestEndEntity");
        raWebHelper.fillCredentials("EcaQa161_TestEndEntity","foo123");
        raWebHelper.clickDownloadPkcs12();
    }

}