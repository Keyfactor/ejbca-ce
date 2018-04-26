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

package org.ejbca.webtest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.WebTestBase;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.helper.CertificateProfileHelper;
import org.ejbca.helper.EndEntityProfileHelper;
import org.ejbca.helper.WebTestHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.Select;
import org.openqa.selenium.support.ui.WebDriverWait;

/**
 * This test verifies that restrictions in the certificate profile is applied for
 * enrollments through the RA web, using On Server- and CSR enrollments.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa125_RaCpRestrictions extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private static EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private static final String cpName = "RestrictCP";
    private static final String eepName = "RestrictEEP";
    private static final String[] csr = {
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

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        certificateProfileSession.removeCertificateProfile(admin, cpName);
        endEntityProfileSession.removeEndEntityProfile(admin, eepName);
        webDriver.quit();
    }

    @Test
    public void testA_cp() {
        // Add Certificate Profile
        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
        CertificateProfileHelper.add(webDriver, cpName, true);

        // Set 'Available Key Algorithms' and 'Available Bit Lengths'
        CertificateProfileHelper.edit(webDriver, cpName);
        Select algorithmSelect = new Select(webDriver.findElement(By.id("cpf:selectavailablekeyalgorithms")));
        WebTestHelper.selectOptions(algorithmSelect, Arrays.asList("RSA"));
        Select bitLengthSelect = new Select(webDriver.findElement(By.id("cpf:selectavailablebitlengths")));
        WebTestHelper.selectOptions(bitLengthSelect, Arrays.asList("1024 bits"));
        CertificateProfileHelper.save(webDriver, true);
    }

    @Test
    public void testB_eep() {
        // Add End Entity Profile
        EndEntityProfileHelper.goTo(webDriver, getAdminWebUrl());
        EndEntityProfileHelper.add(webDriver, eepName, true);

        // Set Certificate Profile in EEP
        EndEntityProfileHelper.edit(webDriver, eepName);
        EndEntityProfileHelper.setDefaultCertificateProfile(webDriver, cpName);
        EndEntityProfileHelper.setAvailableCertificateProfile(webDriver, Arrays.asList(cpName));
        EndEntityProfileHelper.setDefaultCA(webDriver, getCaName());
        EndEntityProfileHelper.setAvailableCAs(webDriver, Arrays.asList(getCaName()));
        EndEntityProfileHelper.save(webDriver, true);
    }

    @Test
    public void testC_onServer() {
        // Go to RA Web -> Make New Request
        webDriver.get(getRaWebUrl());
        webDriver.findElement(By.id("makeRequestButton")).click();
        Select certificateTypeSelect = new Select(webDriver.findElement(By.id("requestTemplateForm:selectEEPOneMenu")));
        certificateTypeSelect.selectByVisibleText(eepName);
        webDriver.findElement(By.id("requestTemplateForm:selectKeyPairGeneration:0")).click();

        // Make sure 'Provide request info' only contains 'CN, Common Name'
        assertEquals("Unexpected number of fields under 'Provide request info'", 1,
                webDriver.findElements(By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label")).size());
        assertEquals("Expected the label to have the value 'CN, Common Name *'", "CN, Common Name *",
                webDriver.findElement(By.xpath("//div[@id='requestInfoForm:requestInfoRendered']//label")).getText());

        // Make sure 'Provide User Credentials' only contains 'Username', 'Enrollment code', 'Confirm enrollment code' and 'Email'
        assertEquals("Unexpected number of fields under 'Provide User Credentials'", 4,
                webDriver.findElements(By.xpath("//div[@id='requestInfoForm:userCredentialsOuterPanel']//label")).size());
        assertEquals("Expected the label to have the value 'Username'", "Username",
                webDriver.findElement(By.xpath("(//div[@id='requestInfoForm:userCredentialsOuterPanel']//label)[1]")).getText());
        assertEquals("Expected the label to have the value 'Enrollment code'", "Enrollment code",
                webDriver.findElement(By.xpath("(//div[@id='requestInfoForm:userCredentialsOuterPanel']//label)[2]")).getText());
        assertEquals("Expected the label to have the value 'Confirm enrollment code'", "Confirm enrollment code",
                webDriver.findElement(By.xpath("(//div[@id='requestInfoForm:userCredentialsOuterPanel']//label)[3]")).getText());
        assertEquals("Expected the label to have the value 'Email'", "Email",
                webDriver.findElement(By.xpath("(//div[@id='requestInfoForm:userCredentialsOuterPanel']//label)[4]")).getText());

        // Click 'Show details' to display Certificate Profile and Key Algorithm
        webDriver.findElement(By.xpath("//div[@id='requestTemplateForm:selectRequestTemplateOuterPanel']//input[@value='Show details']")).click();

        // Assure that the correct values for Certificate Profile and Key Algorithm are selected and that their selections are disabled
        WebElement cpSelect =  webDriver.findElement(By.id("requestTemplateForm:selectCPOneMenu"));
        WebElement kaSelect =  webDriver.findElement(By.id("requestInfoForm:selectAlgorithmOneMenu"));
        assertEquals("Unexpected Certificate Profile selected", cpName + " (default)", cpSelect.getText());
        assertEquals("The Certificate Profile dropdown menu was not disabled", "true", cpSelect.getAttribute("disabled"));
        assertEquals("Unexpected Key Algorithm selected", "RSA 1024 bits", kaSelect.getText());
        assertEquals("The Key Algorithm dropdown menu was not disabled", "true", kaSelect.getAttribute("disabled"));
    }

    @Test
    public void testD_csr() throws InterruptedException {
        // Go to RA Web -> Make New Request
        webDriver.get(getRaWebUrl());

        // A bug in EJBCA requires a wait here, otherwise it results in an XML Parsing Error
        WebDriverWait wait = new WebDriverWait(webDriver, 3);
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("makeRequestButton")));

        webDriver.findElement(By.id("makeRequestButton")).click();
        Select certificateTypeSelect = new Select(webDriver.findElement(By.id("requestTemplateForm:selectEEPOneMenu")));
        certificateTypeSelect.selectByVisibleText(eepName);
        webDriver.findElement(By.id("requestTemplateForm:selectKeyPairGeneration:1")).click();

        // Paste the CSR in the text field and upload
        WebElement csrText = webDriver.findElement(By.id("keyPairForm:certificateRequest"));
        csrText.clear();
        csrText.sendKeys(StringUtils.join(csr, "\n"));
        webDriver.findElement(By.id("keyPairForm:uploadCsrButton")).click();

        // Make sure that there is an error message
        try {
            webDriver.findElement(By.xpath("//li[@class='errorMessage' and contains(text(), \"The key algorithm 'RSA_2048' is not available\")]"));
        } catch (NoSuchElementException e) {
            fail("No/wrong error message displayed when uploading forbidden CSR");
        }
    }
}