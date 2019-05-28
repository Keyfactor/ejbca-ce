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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.WebDriver;

public class EcaQa5_AddEndUserEndEntity extends WebTestBase {
    private static WebDriver webDriver;

    // Helpers
    private static AddEndEntityHelper addEndEntityHelper;

    public static class TestData {
        private static final String ROOTCA_NAME = "ECAQA3";
        private static final String SUBCA_NAME = "subCA ECAQA3";
    }


    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        addEndEntityHelper = new AddEndEntityHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCaAndCryptoToken(TestData.ROOTCA_NAME);
        removeCaByName(TestData.SUBCA_NAME);
        // super
        // afterClass();
    }

    @Test
    public void stepA_AddEndEntityProfile() {
        addEndEntityHelper.openPage(getAdminWebUrl());
        addEndEntityHelper.setEndEntityProfile("EMPTY");
        HashMap<String, String> fields = new HashMap<String, String>(); 
        fields.put("Username", "TestEndEnityEMPTY");
        fields.put("Password (or Enrollment Code)", "foo123");
        fields.put("Confirm Password", "foo123");
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
        fields.put("businessCategory, Organization type",  "QA");
        fields.put("CN, Common name", "TestEndEnityEMPTY");
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
      //  fields.put(" Certificate serial number in hex (e.g. : 1234567890ABCDEF)", "1234567890ABCDEF");
        // fields.put("DC, Domain Component", "primekey_1"); duplicate fields, investigating how to input value for the second one :)
        addEndEntityHelper.fillMsUpnEmail("QA", "Primekey.com");
        addEndEntityHelper.fillFields(fields);
        addEndEntityHelper.triggerBatchGeneration();
        addEndEntityHelper.triggerEmailAddress();
        addEndEntityHelper.clickCheckBoxRfc822();
        addEndEntityHelper.fillFieldEmail("you_mail_box", "primekey.se");
        addEndEntityHelper.setCertificateProfile("ENDUSER");
        addEndEntityHelper.setCa("ManagementCA");
        addEndEntityHelper.setToken("User Generated");
    }
}
