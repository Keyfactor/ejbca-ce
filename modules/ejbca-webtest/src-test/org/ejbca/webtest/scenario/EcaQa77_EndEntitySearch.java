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

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.ejbca.webtest.helper.EndEntityProfileHelper;
import org.ejbca.webtest.helper.RaWebHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa77_EndEntitySearch extends WebTestBase {

    // Helpers
    private static CertificateProfileHelper certificateProfileHelper;
    private static EndEntityProfileHelper endEntityProfileHelper;
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;
    private static RaWebHelper raWebHelper;
    

    public static class TestData {
        private static final String SHORTVALIDITY_CERTIFICATE_PROFILE_NAME = "ShortValidity";
        private static final String SHORTVALIDITY_ENDENTITY_PROFILE_NAME = "ShortValidity";
        private static final String CA_NAME = "ManagementCA";
        
        static final String[] CERTIFICATE_REQUEST_PEM = new String[] {
                "-----BEGIN CERTIFICATE REQUEST-----", 
                "MIICZzCCAU8CAQAwIjELMAkGA1UEBhMCVVMxEzARBgNVBAMMClJlc3RyaWN0Q04w", 
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwyIsyw3HB+8yxOF9BOfjG", 
                "zLoQIX7sLg1lXk1miLyU6wYmuLnZfZrr4pjZLyEr2iP92IE97DeK/8y2827qctPM", 
                "y4axmczlRTrEZKI/bVXnLOrQNw1dE+OVHiVoRFa5i4TS/qfhNA/Gy/eKpzxm8LT7", 
                "+folAu92HwbQ5H8fWQ/l+ysjTheLMyUDaK83+NvYAL9Gfl29EN/TTrRzLKWoXrlB", 
                "Ed7PT2oCBgrvF7pHsrry2O3yuuO2hoF5RQTo9BdBaGvzxGdweYTvdoLWfZm1zGI+", 
                "CW0lprBdjagCC4XAcWi5OFcxjrRA9WA6Cu1q4Hn+eJEdCNHVvqss2rz6LOWjAQAr", 
                "AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEA1JlwrFN4ihTZWICnWFb/kzcmvjcs", 
                "0xeerNZQAEk2FJgj+mKVNrqCRWr2iaPpAeggH8wFoZIh7OvhmIZNmxScw4K5HhI9", 
                "SZD+Z1Dgkj8+bLAQaxvw8sxXLdizcMNvbaXbzwbAN9OUkXPavBlik/b2JLafcEMM", 
                "8IywJOtJMWemfmLgR7KAqDj5520wmXgAK6oAbbMqWUip1vz9oIisv53n2HFq2jzq", 
                "a5d2WKBq5pJY19ztQ17HwlGTI8it4rlKYn8p2fDuqxLXiBsX8906E/cFRN5evhWt", 
                "zdJ6yvdw3HQsoVAVi0GDHTs2E8zWFoYyP0byzKSSvkvQR363LQ0bik4cuQ==", 
                "-----END CERTIFICATE REQUEST-----"
        };
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        WebDriver webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
        endEntityProfileHelper = new EndEntityProfileHelper(webDriver);
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        raWebHelper = new RaWebHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        // removeEndEntityByUsername(TestData.END_ENTITY_NAME_1);
        // removeEndEntityByUsername(TestData.END_ENTITY_NAME_2);
        // TODO remove cert profile
        // TODO remove EE profile
        //afterClass(); // TODO put this back
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
    
    
    // replaced by stepE
    /*
    @Test
    public void stepC_addEndEntity_sven() {
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
*/

    @Test
    public void stepD_addEndEntity_otto() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("ShortValidity");
        HashMap <String, String> fields = new HashMap<>();
        fields.put("Username", "otto");
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", "Otto");
        fields.put("C, Country (ISO 3166)", "DE");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.addEndEntity();
    }

    
    // For whatever reason the actions for creating an EndEntity need to be in separate steps. Otherwise, when you press 'Download PEM', you'll get a JSF parsingexception
    @Test
    public void stepE1_CreateSven() {
        raWebHelper.openPage(this.getRaWebUrl());
        raWebHelper.makeNewCertificateRequest();
    }

    @Test
    public void stepE2_CreateSven() {
        raWebHelper.selectCertificateTypeByEndEntityName(TestData.SHORTVALIDITY_ENDENTITY_PROFILE_NAME);
        raWebHelper.selectKeyPairGenerationProvided();
    }

    @Test
    public void stepE3_CreateSven() {
        raWebHelper.fillClearCsrText(StringUtils.join(TestData.CERTIFICATE_REQUEST_PEM, "\n"));
    }

    @Test
    public void stepE4_CreateSven() {
        raWebHelper.clickUploadCsrButton();
    }

    @Test
    public void stepE5_CreateSven() {
        raWebHelper.fillMakeRequestEditCommonName("sven");
    }

    @Test
    public void stepE6_CreateSven() {
        raWebHelper.fillUsername("sven");
    }
    
    @Test
    public void stepE7_CreateSven() {
        raWebHelper.clickDownloadPem();
    }

    
    @Test
    public void stepF_searchEndEntity_otto() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic();
        searchEndEntitiesHelper.fillSearchCriteria("otto",null,null,null);
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
    }
    
}
