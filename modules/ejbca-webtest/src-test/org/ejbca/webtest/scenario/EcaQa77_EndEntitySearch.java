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

import java.util.Collections;
import java.util.HashMap;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa77_EndEntitySearch extends WebTestBase {

    private static WebDriver webDriver;

    // Helpers
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    

    public static class TestData {
        private static final String ROOTCA_NAME = "ECAQA5";
        private static final String SUBCA_NAME = "subCA ECAQA5";
        private static final String END_ENTITY_NAME_1 = "TestEndEntityEMPTY_1";
        private static final String END_ENTITY_NAME_2 = "TestEndEntityEMPTY_2";
        private static final String SHORTVALIDITY_CERTIFICATE_PROFILE_NAME = "ShortValidity";
        private static final String SHORTVALIDITY_ENDENTITY_PROFILE_NAME = "ShortValidity";
        private static final String CA_NAME = "ManagementCA";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
//        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
//        removeCaByName(TestData.SUBCA_NAME);
//        removeEndEntityByUsername(TestData.END_ENTITY_NAME_1);
//        removeEndEntityByUsername(TestData.END_ENTITY_NAME_2);
//        removeEndEntityByUsername(TestData.END_ENTITY_NAME_3);

        //afterClass();
    }

    @Test
    public void stepA_addCertificateProfile() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.cloneCertificateProfile("SERVER", TestData.SHORTVALIDITY_CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.openEditCertificateProfilePage(TestData.SHORTVALIDITY_CERTIFICATE_PROFILE_NAME);
        certificateProfileHelper.editCertificateProfile(null, null, null, null, "2d");
        certificateProfileHelper.saveCertificateProfile();
    }
    
    @Test
    public void stepB_addEndEntityProfile() {
        endEntityProfileHelper.openPage(getAdminWebUrl());
        endEntityProfileHelper.addEndEntityProfile(TestData.SHORTVALIDITY_ENDENTITY_PROFILE_NAME);
        // Set Certificate Profile in EEP
        endEntityProfileHelper.openEditEndEntityProfilePage(TestData.SHORTVALIDITY_ENDENTITY_PROFILE_NAME);
        endEntityProfileHelper.editEndEntityProfile(
                TestData.SHORTVALIDITY_CERTIFICATE_PROFILE_NAME,
                Collections.singletonList(TestData.SHORTVALIDITY_CERTIFICATE_PROFILE_NAME),
                TestData.CA_NAME,
                Collections.singletonList(getCaName())
        );
        
        endEntityProfileHelper.addSubjectAttribute("dn", "C, Country (ISO 3166)");
        
        endEntityProfileHelper.saveEndEntityProfile();
        
    }
    @Test
    public void stepC_addEndEntity() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("ShortValidity");
        HashMap <String, String> fields = new HashMap<>();
        fields.put("Username", "sven");
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", "Sven");
        fields.put("C, Country (ISO 3166)", "SE");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.addEndEntity();

    }

}
