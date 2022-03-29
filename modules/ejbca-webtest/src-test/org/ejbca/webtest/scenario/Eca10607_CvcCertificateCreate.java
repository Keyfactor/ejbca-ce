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

import java.util.HashMap;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.RaWebUseUsernameRequestHelper;
import org.ejbca.webtest.helper.CaHelper.CaType;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper.TerminalType;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * Test verifies CV certificate enrollment in RA web.
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Eca10607_CvcCertificateCreate extends WebTestBase {
    // Helpers
    private static CaHelper caHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    private static CryptoTokenHelper cryptoTokenHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static RaWebHelper raWebHelper;
    private static RaWebUseUsernameRequestHelper raWebUseUsernameRequestHelper; 

    public static class TestData {
        private static final String ROOTCA_NAME = "ECA10607";
        private static final String ROOTCA_DN = "CN=ECA10607,C=SE";
        private static final String ROOTCA_VALIDITY = "1y";
        static final String CERTIFICATE_PROFILE_NAME = "Eca10607CertProfile";
        static final String END_ENTITY_PROFILE_NAME = "Eca10607EEProfile";
        static final String END_ENTITY_NAME = "Eca10607TestUser";
        static final String END_ENTITY_PASSWORD = "foo123";
        static final String END_ENTITY_COMMON_NAME = "CVC1";
        static final String END_ENTITY_COUNTRY = "SE";
        static final String END_ENTITY_TOKEN = "User Generated";
        static final String KEY_ALGORITHM = "RSA 2048 bits";
        static final String CVC_REQ_PEM = "-----BEGIN CERTIFICATE REQUEST-----\n"+
                "fyGCAjZ/ToIBLF8pAQB/SYIBFQYKBAB/AAcCAgIBAoGCAQCZINKfqoA4Xb6wxVv9\n"+
                "FOqi7aNcGMslTeW+VROF1AWq5xJAVhNsPihEAOIRxJir4LsHlMSnrSwTzXl4G0Nt\n"+
                "xSTqJVvyrPK85821HJ+LjmL/SQbi9WMVGwo5s/OHS7Bz/jkFq2uLrK45NLw5+SsP\n"+
                "pUr9GRCCdsNgtV5BtD4DGYI/E5eCrt6dFXwbWMYAVa8Omh/yZjsPqglz8TlE2rWV\n"+
                "/X+7pDDrNRX/qdCobuOQMaIeZfpq30wKFlGrBzD4RL1c0+Z4Wzm6YRWy8cbYdQgq\n"+
                "XnpeMMmKQFXOJMl1PcRm6qjI1XmMO1uMB/3y/zXyuV1R6DKewXAtn4j2rym4eYX8\n"+
                "IHKXggMBAAFfIAtTRUNWQzEwMDAwMV83ggEATUE9C3cWHAeFM5tB7iYQZBAGNDSF\n"+
                "GRd0mDNovXFOKyNpn0BeFqnfAjQ90OwCpFtDxiRvQwWuWmzdyo0BE/8J6AtDGlZL\n"+
                "/mcFzG6y2JPjBKOCNYvl8H2cXEjlJOuLXqm/W2sjf9SQT/rsw+ZOzcORNAXpYVns\n"+
                "4mZKb0qpxtkJ6Pm5GWFg8lMaInPiZ5peeDySjZEGHgngrngPhdZNpMfIl7wMYiHp\n"+
                "XfSV4tUkkAi6L60hyKvH61iQM6UJNuTQ+P8U6qxlcllIqnVok3zyjKlfW3RDVhAE\n"+
                "DWiXmaeE5WYlRwGtMqTtE4w36ayR2eUssfGvcAPXi3YWj1apXI+DJIjJ8A==\n"+
                "-----END CERTIFICATE REQUEST-----";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
        raWebUseUsernameRequestHelper = new RaWebUseUsernameRequestHelper(webDriver);
    }

    @AfterClass
    public static void exit() {
        // Remove generated artifacts
        cleanup();
        // super
        afterClass();
    }

    @Test
    public void A_createRootCa() {
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.ROOTCA_NAME);
        // Set CA Type, Subject DN and Validity
        caHelper.setCaType(CaType.CVC);
        caHelper.setSubjectDn(TestData.ROOTCA_DN);
        caHelper.setValidity(TestData.ROOTCA_VALIDITY);
        // Save the CA and check that save was successful
        caHelper.createCa();
        caHelper.assertExists(TestData.ROOTCA_NAME);
    }

    @Test
    public void B_checkCryptoToken() {
        cryptoTokenHelper.openPage(getAdminWebUrl());
        // Check that Crypto Token exists
        cryptoTokenHelper.assertTokenExists(TestData.ROOTCA_NAME);
    }

    @Test
    public void testA_AddCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.selectAvailableCa(TestData.ROOTCA_NAME);
        certificateProfileHelper.setCvcTerminalType(TerminalType.ST);
        certificateProfileHelper.saveCertificateProfile();
        certificateProfileHelper.assertCertificateProfileNameExists(TestData.CERTIFICATE_PROFILE_NAME);
    }

    @Test
    public void testB_AddEndEntityProfile() {    
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.END_ENTITY_PROFILE_NAME);
        endEntityProfileHelper.addSubjectDnAttribute("C, Country (ISO 3166)");
        endEntityProfileHelper.selectAvailableCp(TestData.CERTIFICATE_PROFILE_NAME);
        endEntityProfileHelper.selectDefaultCp(TestData.CERTIFICATE_PROFILE_NAME);
        endEntityProfileHelper.saveEndEntityProfile();
        // Verify that we have a certificate profile
        endEntityProfileHelper.assertEndEntityProfileNameExists(TestData.END_ENTITY_PROFILE_NAME);
    }

    @Test
    public void testC_AddEndEntity() {    
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile(TestData.END_ENTITY_PROFILE_NAME);
        addEndEntityHelper.setCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        HashMap<String, String> fields = new HashMap<>();
        fields.put("Username", TestData.END_ENTITY_NAME);
        fields.put("Password (or Enrollment Code)", TestData.END_ENTITY_PASSWORD);
        fields.put("Confirm Password", TestData.END_ENTITY_PASSWORD);
        fields.put("CN, Common name", TestData.END_ENTITY_COMMON_NAME);
        fields.put("C, Country (ISO 3166)", TestData.END_ENTITY_COUNTRY);
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.setCa(TestData.ROOTCA_NAME);
        addEndEntityHelper.setToken(TestData.END_ENTITY_TOKEN);
        addEndEntityHelper.addEndEntity();
        // Verify that we have added the end entity
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME);
    }

    @Test
    public void testD_EnrollCvCertificateWithUsername() {
        raWebUseUsernameRequestHelper.openPage(getRaWebUrl());
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // NOPMD
        }
        raWebUseUsernameRequestHelper.clickToEnrollUseUsername();
        raWebUseUsernameRequestHelper.fillEnrollUsernameAndCode(TestData.END_ENTITY_NAME, TestData.END_ENTITY_PASSWORD);
        raWebUseUsernameRequestHelper.clickCheckButton();
        raWebUseUsernameRequestHelper.selectKeyAlgorithm(TestData.KEY_ALGORITHM);
        raWebUseUsernameRequestHelper.fillClearCsrText(TestData.CVC_REQ_PEM);
        try {
            Thread.sleep(200);
        } catch (InterruptedException e) {
            // NOPMD
        }
        raWebUseUsernameRequestHelper.clickUploadCsrButton();
        raWebUseUsernameRequestHelper.clickEnrollDownloadPemButton();
    }

    private static void cleanup() {
        removeEndEntityByUsername(TestData.END_ENTITY_NAME);
        removeCertificateByUsername(TestData.END_ENTITY_NAME);
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        removeEndEntityProfileByName(TestData.END_ENTITY_PROFILE_NAME);
        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
    }
}
