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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AddEndEntityHelper;
import org.ejbca.webtest.helper.SearchEndEntitiesHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa5_AddEndUserEndEntity extends WebTestBase {

    private static WebDriver webDriver;

    // Helpers
    private static AddEndEntityHelper addEndEntityHelper;
    private static SearchEndEntitiesHelper searchEndEntitiesHelper;

    public static class TestData {
        private static final String ROOTCA_NAME = "ECAQA5";
        private static final String SUBCA_NAME = "subCA ECAQA5";
        private static final String END_ENTITY_NAME_1 = "TestEndEntityEMPTY_1";
        private static final String END_ENTITY_NAME_2 = "TestEndEntityEMPTY_2";
        private static final String END_ENTITY_NAME_3 = "TestEndEntityEMPTY_3";

    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        webDriver = getWebDriver();
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
        searchEndEntitiesHelper = new SearchEndEntitiesHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
        removeCaByName(TestData.SUBCA_NAME);
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_1);
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_2);
        removeEndEntityByUsername(TestData.END_ENTITY_NAME_3);

        afterClass();
    }

    @Test
    public void stepA_AddEndEntitySubjectDn1of3() throws InterruptedException {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<String, String>();
        
        
        // 1 of 3
        fields.put("Username", TestData.END_ENTITY_NAME_1);
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", TestData.END_ENTITY_NAME_1);
        fields.put("ST, State or Province", "Germany");
        fields.put("OU, Organizational Unit", "QA");
        fields.put("L, Locality", "Europe");
        fields.put("Jurisdiction Locality [EV Certificate]", "aJurisdictionLocality");
        fields.put("unstructuredName, Domain name (FQDN)", "pkiemail.qa.primekey.se");
        fields.put("postalAddress", "#301d0c0f536f6d6520737472656574203132330c0a534f4d4520504c41434");
        fields.put("name", "Tester");
        fields.put("Jurisdiction State or Province [EV Certificate]", "aJurisdictionState");
        fields.put("UID, Unique Identifier", "ECAQA5");
        fields.put("NIF, Tax ID number, for individuals (Spain)", "1234");
        fields.put("CIF, Tax ID code, for companies (Spain)", "5678");
        fields.put("unstructuredAddress, IP address", "127.0.0.1");

        addEndEntityHelper.fillMsUpnEmail("QA", "Primekey.com");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.triggerBatchGeneration();
        addEndEntityHelper.triggerEmailAddress();
        addEndEntityHelper.clickCheckBoxRfc822();
        addEndEntityHelper.fillFieldEmail("you_mail_box", "primekey.se");
        addEndEntityHelper.setCertificateProfile("ENDUSER");
        addEndEntityHelper.setCa("ManagementCA");
        addEndEntityHelper.setToken("User Generated");
        addEndEntityHelper.fillCertificateSerialNumberInHexl("1234567890ABCDEF");
        addEndEntityHelper.addEndEntity();
        
        // verify that success message appeared
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME_1);
    }

    @Test
    public void stepB_AddEndEntitySubjectDn2of3() throws InterruptedException {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<String, String>();
        fields.put("Username", TestData.END_ENTITY_NAME_2);
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", TestData.END_ENTITY_NAME_2);
        fields.put("businessCategory, Organization type",  "QA");
        fields.put("postalCode", "12345");
        fields.put("O, Organization", "QA");
        fields.put("pseudonym", "tester");
        fields.put("DC, Domain Component", "primekey");
        fields.put("surname, Surname (last name)", "Raudsep");
        fields.put("serialNumber, Serial number (in DN)", "123456780");
        fields.put("C, Country (ISO 3166)", "DE");
        fields.put("initials, First name abbreviation", "JS");
        fields.put("streetAddress", "The street");
        fields.put("dnQualifier, DN Qualifier", "aDnQualifier");
        fields.put("givenName, Given name (first name)",  "John");
        fields.put("Jurisdiction Country (ISO 3166) [EV Certificate]", "DE");
        fields.put("telephoneNumber", "123456789");
        fields.put("title, Title", "Prof.");

        addEndEntityHelper.fillMsUpnEmail("QA", "Primekey.com");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.triggerBatchGeneration();
        addEndEntityHelper.triggerEmailAddress();
        addEndEntityHelper.clickCheckBoxRfc822();
        addEndEntityHelper.fillFieldEmail("you_mail_box", "primekey.se");
        addEndEntityHelper.setCertificateProfile("ENDUSER");
        addEndEntityHelper.setCa("ManagementCA");
        addEndEntityHelper.setToken("User Generated");
        addEndEntityHelper.fillCertificateSerialNumberInHexl("1234567890ABCDEF");
        addEndEntityHelper.addEndEntity();

        // verify that success message appeared
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME_2);
    }
    
    @Test
    public void stepC_AddEndEntitySubjectDn3of3() throws InterruptedException {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<String, String>();

        fields.put("Username", TestData.END_ENTITY_NAME_3);
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
        fields.put("CN, Common name", TestData.END_ENTITY_NAME_3);
        fields.put("Uniform Resource Identifier (URI)", "/contact-us/");
        fields.put("Kerberos KPN, Kerberos 5 Principal Name", "primary/instance@REALM");
        fields.put("MS GUID, Globally Unique Identifier",  "21EC20203AEA4069A2DD08002B30309D");
        fields.put("DNS Name", "primekey.se");
        fields.put("Permanent Identifier", "123456789");
        fields.put("Directory Name (Distinguished Name)", "CN=aDirectoryName");
        fields.put("IP Address",  "127.0.0.1");
        fields.put("Country of residence (ISO 3166)", "DE");
        fields.put("Country of citizenship (ISO 3166)", "DE");
        fields.put("Place of birth", "Germany");
        fields.put("Date of birth (YYYYMMDD)", "19710101");
        fields.put("Gender (M/F)", "F");

        addEndEntityHelper.fillMsUpnEmail("QA", "Primekey.com");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.triggerBatchGeneration();
        addEndEntityHelper.triggerEmailAddress();
        addEndEntityHelper.clickCheckBoxRfc822();
        addEndEntityHelper.fillFieldEmail("you_mail_box", "primekey.se");
        addEndEntityHelper.setCertificateProfile("ENDUSER");
        addEndEntityHelper.setCa("ManagementCA");
        addEndEntityHelper.setToken("User Generated");
        addEndEntityHelper.fillCertificateSerialNumberInHexl("1234567890ABCDEF");
        addEndEntityHelper.addEndEntity();

        // verify that success message appeared
        addEndEntityHelper.assertEndEntityAddedMessageDisplayed(TestData.END_ENTITY_NAME_3);

    }
    
    @Test
    public void stepD_SearchEndEntitySubjectDn1of3() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());
        
        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic(); //Note: the search panel needs to be in "basic mode" for 'fillSearchCriteria' method to work properly.
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME_1, null, null, null);
        
        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
    }
    
    @Test
    public void stepE_SearchEndEntitySubjectDn2of3() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());

        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic(); //Note: the search panel needs to be in "basic mode" for 'fillSearchCriteria' method to work properly.
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME_2, null, null, null);

        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
    }
    
    @Test
    public void stepF_SearchEndEntitySubjectDn3of3() {
        searchEndEntitiesHelper.openPage(getAdminWebUrl());

        searchEndEntitiesHelper.switchViewModeFromAdvancedToBasic(); //Note: the search panel needs to be in "basic mode" for 'fillSearchCriteria' method to work properly.
        searchEndEntitiesHelper.fillSearchCriteria(TestData.END_ENTITY_NAME_3, null, null, null);

        searchEndEntitiesHelper.clickSearchByUsernameButton();
        searchEndEntitiesHelper.assertNumberOfSearchResults(1);
    }
}
