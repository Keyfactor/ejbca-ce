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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.WebTestBase;
import org.ejbca.helper.AuditLogHelper;
import org.ejbca.helper.CertificateProfileHelper;
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
import org.openqa.selenium.support.ui.Select;

/**
 * Verifies that changes made to Certificate Profiles in the AdminWeb
 * propagates to the backend.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa74_CpBackend extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);

    private static final String cpName = "ECAQA-74-CertificateProfile";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        certificateProfileSession.removeCertificateProfile(admin, cpName);
        webDriver.quit();
    }

    @Test
    public void a_addCp() {
        AuditLogHelper.resetFilterTime();
        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
        CertificateProfileHelper.add(webDriver, cpName, true);

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Create", "Success", null,
                Arrays.asList("New certificate profile " + cpName + " added successfully."));
    }

    @Test
    public void b_overrideOptions() {
        AuditLogHelper.resetFilterTime();
        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
        CertificateProfileHelper.edit(webDriver, cpName);

        // Set 'Available Key Algorithms', 'Available ECDSA curves', 'Available Bit Lengths' and 'Signature Algorithm'
        WebTestHelper.selectOptions(new Select(webDriver.findElement(By.id("cpf:selectavailablekeyalgorithms"))),
                Arrays.asList("ECDSA", "RSA"));
        WebTestHelper.selectOptions(new Select(webDriver.findElement(By.id("cpf:selectavailableeccurves"))),
                Arrays.asList("prime256v1 / secp256r1 / P-256"));
        WebTestHelper.selectOptions(new Select(webDriver.findElement(By.id("cpf:selectavailablebitlengths"))),
                Arrays.asList("2048 bits", "3072 bits", "4096 bits"));
        new Select(webDriver.findElement(By.id("cpf:selectsignaturealgorithm"))).selectByVisibleText("SHA256WithRSA");

        // Set 'Validity'
        WebElement validity = webDriver.findElement(By.id("cpf:textfieldvalidity"));
        validity.clear();
        validity.sendKeys("365d");

        // Clicky stuff
        webDriver.findElement(By.id("cpf:checkallowvalidityoverride")).click();
        webDriver.findElement(By.id("cpf:checkallowextensionoverride")).click();
        webDriver.findElement(By.id("cpf:checkallowdnoverride")).click();
        webDriver.findElement(By.id("cpf:checkallowdnoverrideeei")).click();
        webDriver.findElement(By.id("cpf:checkallowkeyusageoverride")).click();
        webDriver.findElement(By.id("cpf:checkallowbackdatedrevokation")).click();
        webDriver.findElement(By.id("cpf:checkUseCertificateStorage")).click();
        webDriver.findElement(By.id("cpf:checkStoreCertificateData")).click();
        CertificateProfileHelper.save(webDriver, true);

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Edit", "Success", null,
                Arrays.asList("msg=Edited certificateprofile " + cpName, "encodedvalidity=1y", "allowvalidityoverride=true",
                        "allowextensionoverride=true", "allowdnoverride=true", "allowdnoverridebyeei=true",
                        "allowbackdatedrevokation=true", "usecertificatestorage=false", "storecertificatedata=false",
                        "availablekeyalgorithms=[ECDSA, RSA]", "availableeccurves=[prime256v1]",
                        "availablebitlengths=[2048, 3072, 4096]", "minimumavailablebitlength=2048",
                        "maximumavailablebitlength=4096", "signaturealgorithm=SHA256WithRSA", "allowkeyusageoverride=true"));
    }

    @Test
    public void c_certificatePoliciesOptions() {
        AuditLogHelper.resetFilterTime();
        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
        CertificateProfileHelper.edit(webDriver, cpName);

        // More clicky stuff
        webDriver.findElement(By.id("cpf:cbbasicconstraintscritical")).click();
        webDriver.findElement(By.id("cpf:cbauthoritykeyidentifier")).click();
        webDriver.findElement(By.id("cpf:cbsubjectkeyidentifier")).click();
        webDriver.findElement(By.id("cpf:cbkeyusagecritical")).click();
        webDriver.findElement(By.id("cpf:keyUsageNonRepudiation")).click();
        webDriver.findElement(By.id("cpf:keyUsageDataEncipherment")).click();
        webDriver.findElement(By.id("cpf:cbextendedkeyusagecritical")).click();
        webDriver.findElement(By.id("cpf:checkusecertificatepolicies")).click();

        // Check that new fields appeared
        try {
            webDriver.findElement(By.xpath("//input[contains(@id, 'textfieldcertificatepolicyid')]"));
            webDriver.findElement(By.xpath("//input[contains(@id, 'buttonaddpolicy')]"));
            webDriver.findElement(By.xpath("//input[contains(@value, 'No Policy Qualifier') and contains(@class, 'selected')]"));
            webDriver.findElement(By.xpath("//input[contains(@value, 'User Notice Text') and contains(@class, 'notSelected')]"));
            webDriver.findElement(By.xpath("//input[contains(@value, 'CPS URI') and contains(@class, 'notSelected')]"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'Certificate Policies'");
        }
    }

    @Test
    public void d_crlDistributionPointsEnable() {
        webDriver.findElement(By.id("cpf:cbsubjectalternativenamecritical")).click();
        webDriver.findElement(By.id("cpf:cbissueralternativenamecritical")).click();
        webDriver.findElement(By.id("cpf:checksubjectdirattributes")).click();
        webDriver.findElement(By.id("cpf:checknameconstraints")).click();
        webDriver.findElement(By.id("cpf:cbcrldistributionpoint")).click();

        // Check that new fields appeared
        try {
            assertEquals("'Use CA defined CRL Distribution Point' was not disabled by default", "Off",
                    webDriver.findElement(By.id("cpf:cbusedefaultcrldistributionpoint")).getAttribute("value"));
            assertEquals("'CRL Distribution Point URI' had unexpected default value",
                    getPublicWebUrl() + "publicweb/webdist/certdist?cmd=crl&issuer=CN=TestCA,O=AnaTom,C=SE",
                    webDriver.findElement(By.id("cpf:textfieldcrldisturi")).getAttribute("value"));
            assertEquals("'CRL Issuer' had unexpected default value", "CN=TestCA,O=AnaTom,C=SE",
                    webDriver.findElement(By.id("cpf:textfieldcrlissuer")).getAttribute("value"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'X.509v3 extensions'");
        }
    }

    @Test
    public void e_crlDistributionPointsOptions() {
        // Enable 'Use CA defined CRL Distribution Point' and check that fields become disabled
        webDriver.findElement(By.id("cpf:cbusedefaultcrldistributionpoint")).click();
        assertFalse("'CRL Distribution Point URI' did not become disabled",
                webDriver.findElement(By.id("cpf:textfieldcrldisturi")).isEnabled());
        assertFalse("'CRL Distribution Point URI' did not become disabled",
                webDriver.findElement(By.id("cpf:textfieldcrlissuer")).isEnabled());

        // Enable 'Freshest CRL' and check that new fields appeared
        webDriver.findElement(By.id("cpf:cbusefreshestcrl")).click();
        try {
            assertEquals("'Use CA Defined Freshest CRL' was not disabled by default", "Off",
                    webDriver.findElement(By.id("cpf:cbusecadefinedfreshestcrl")).getAttribute("value"));
            assertEquals("'Freshest CRL URI' had unexpected default value",
                    getPublicWebUrl() + "publicweb/webdist/certdist?cmd=deltacrl&issuer=CN=TestCA,O=AnaTom,C=SE",
                    webDriver.findElement(By.id("cpf:textfieldfreshestcrluri")).getAttribute("value"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'X.509v3 extensions'");
        }

        // Enable 'Use CA Defined Freshest CRL' and 'Authority Information Access' and check that fields appear/are disabled
        webDriver.findElement(By.id("cpf:cbusecadefinedfreshestcrl")).click();
        webDriver.findElement(By.id("cpf:checkuseauthorityinformationaccess")).click();
        try {
            assertFalse("'Freshest CRL URI' did not become disabled",
                    webDriver.findElement(By.id("cpf:textfieldfreshestcrluri")).isEnabled());
            assertEquals("'Authority Information Access' was not enabled by default", "On",
                    webDriver.findElement(By.id("cpf:checkuseauthorityinformationaccess")).getAttribute("value"));
            assertEquals("'Use CA defined OCSP locator' was not disabled by default", "Off",
                    webDriver.findElement(By.id("cpf:checkusedefaultocspservicelocator")).getAttribute("value"));
            assertEquals("'OCSP Service Locator URI' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:textfieldocspservicelocatoruri")).getAttribute("value"));
            assertEquals("'CA issuer URI' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:caIssuers:textfieldcaissueruri")).getAttribute("value"));
            webDriver.findElement(By.id("cpf:caIssuers:buttonaddcaissueruri"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'X.509v3 extensions'");
        }

        // Enable 'Use CA defined OCSP locator' and 'Private Key Usage Period' and check that new fields become enabled
        webDriver.findElement(By.id("cpf:checkusedefaultocspservicelocator")).click();
        webDriver.findElement(By.id("cpf:cbuseprivkeyusageperiodnotbefore")).click();
        WebElement startOffset = null;
        WebElement periodLength = null;
        try {
            startOffset = webDriver.findElement(By.id("cpf:textfieldprivkeyusageperiodstartoffset"));
            assertTrue("'Start offset' did not become enabled", startOffset.isEnabled());
            assertEquals("'Start offset' had unexpected default value", "0d", startOffset.getAttribute("value"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'X.509v3 extensions'");
        }

        // Set 'Start offset' and enable 'Period length'
        startOffset.clear();
        startOffset.sendKeys("1d");
        webDriver.findElement(By.id("cpf:cbuseprivkeyusageperiodnotafter")).click();
        try {
            periodLength = webDriver.findElement(By.id("cpf:textfieldprivkeyusageperiodlength"));
            assertTrue("'Period length' did not become enabled", periodLength.isEnabled());
            assertEquals("'Period length' had unexpected default value", "2y", periodLength.getAttribute("value"));
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'X.509v3 extensions'");
        }

        // Set 'Period length' and save
        periodLength.clear();
        periodLength.sendKeys("360d");
        CertificateProfileHelper.save(webDriver, true);
    }

    @Test
    public void f_verifyAuditLog() {
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Edit", "Success", null,
                Arrays.asList("msg=Edited certificateprofile " + cpName, "basicconstraintscritical=false",
                        "usesubjectkeyidentifier=false", "useauthoritykeyidentifier=false",
                        "subjectalternativenamecritical=true", "issueralternativenamecritical=true",
                        "usecrldistributionpoint=true", "usedefaultcrldistributionpoint=true", "usefreshestcrl=true",
                        "usecadefinedfreshestcrl=true", "usecertificatepolicies=true",
                        "keyusage=[true, false, true, true, false, false, false, false, false]",
                        "keyusagecritical=false", "extendedkeyusagecritical=true", "nameconstraintscritical=false",
                        "usesubjectdirattributes=true", "usenameconstraints=true", "useauthorityinformationaccess=true",
                        "usedefaultocspservicelocator=true", "useprivkeyusageperiodnotbefore=true",
                        "useprivkeyusageperiod=true", "useprivkeyusageperiodnotafter=true",
                        "privkeyusageperiodstartoffset=86400", "privkeyusageperiodlength=31104000"));
    }

    @Test
    public void g_qcStatementsEnable() {
        AuditLogHelper.resetFilterTime();
        CertificateProfileHelper.goTo(webDriver, getAdminWebUrl());
        CertificateProfileHelper.edit(webDriver, cpName);

        // Enable 'Qualified Certificates Statements' and check that new fields appear
        webDriver.findElement(By.id("cpf:checkuseqcstatement")).click();
        try {
            assertFalse("'PKIX QCSyntax-v2' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkpkixqcsyntaxv2")).isSelected());
            assertEquals("'Semantics Identifier (OID)' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:textfieldqcsemanticsid")).getAttribute("value"));
            assertEquals("'Name Registration Authorities' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:textfieldqcstatementraname")).getAttribute("value"));
            assertFalse("'ETSI Qualified Certificate compliance' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkqcetsiqcompliance")).isSelected());
            assertFalse("'ETSI Qualified Signature/Seal Creation Device' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkqcetsisignaturedevice")).isSelected());
            assertFalse("'ETSI transaction value limit' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkqcetsivaluelimit")).isSelected());
            assertEquals("'Currency' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitcur")).getAttribute("value"));
            assertEquals("'Amount' did not have the expected default value", "0",
                    webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimit")).getAttribute("value"));
            assertEquals("'Exponent' did not have the expected default value", "0",
                    webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitexp")).getAttribute("value"));
            assertFalse("'ETSI retention period' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkqcetsiretentionperiod")).isSelected());
            assertEquals("'Value (years)' did not have the expected default value", "0",
                    webDriver.findElement(By.id("cpf:textfieldqcetsiretentionperiod")).getAttribute("value"));
            assertEquals("'ETSI type' did not have the expected default value", "Unused",
                    new Select(webDriver.findElement(By.id("cpf:qcetsitype"))).getFirstSelectedOption().getText());
            assertEquals("'ETSI PDS URL' was not empty by default", "",
                    webDriver.findElement(By.id("cpf:qcetsipdsgroup:0:textfieldqcetsipdsurl")).getAttribute("value"));
            assertEquals("'ETSI PDS Language' did not have the expected default value", "English",
                    new Select(webDriver.findElement(By.id("cpf:qcetsipdsgroup:0:qcetsipdslang"))).getFirstSelectedOption().getText());
            assertFalse("'Delete' was not disabled by default",
                    webDriver.findElement(By.id("cpf:qcetsipdsgroup:0:buttondeleteqcetsipds")).isEnabled());
            assertTrue("'Add Another' was not enabled by default",
                    webDriver.findElement(By.id("cpf:qcetsipdsgroup:buttonaddqcetsipds")).isEnabled());
            assertFalse("'Custom QC-statements String' was not disabled by default",
                    webDriver.findElement(By.id("cpf:checkqccustomstring")).isSelected());
            assertFalse("'Object Identifier (OID)' was not disabled by default",
                    webDriver.findElement(By.id("cpf:textfieldqccustomstringoid")).isEnabled());
            assertFalse("'Custom QC-statements Text' was not disabled by default",
                    webDriver.findElement(By.id("cpf:textfieldqccustomstringtext")).isEnabled());
        } catch (NoSuchElementException e) {
            fail("Expected fields did not appear under 'QC Statements extension'");
        }
    }

    @Test
    public void h_qcStatementsEdit() {
        // Click boxes and fill text fields 
        webDriver.findElement(By.id("cpf:checkpkixqcsyntaxv2")).click();
        webDriver.findElement(By.id("cpf:textfieldqcsemanticsid")).sendKeys("text");
        webDriver.findElement(By.id("cpf:textfieldqcstatementraname")).sendKeys("text");
        webDriver.findElement(By.id("cpf:checkqcetsiqcompliance")).click();
        webDriver.findElement(By.id("cpf:checkqcetsisignaturedevice")).click();
        webDriver.findElement(By.id("cpf:checkqcetsivaluelimit")).click();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitcur")).clear();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitcur")).sendKeys("text");
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimit")).clear();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimit")).sendKeys("text");
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitexp")).clear();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitexp")).sendKeys("text");
        webDriver.findElement(By.id("cpf:checkqcetsiretentionperiod")).click();

        // Check that two errors appear
        assertEquals("Expected 2 error messages", 2,
                webDriver.findElements(By.xpath("//td[contains(text(), 'Only decimal numbers are allowed in ETSI Value Limit Amount and Exponent fields.')]")).size());

        // Clear invalid fields and keep doing clicky stuff
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitcur")).clear();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimit")).clear();
        webDriver.findElement(By.id("cpf:textfieldqcetsivaluelimitexp")).clear();
        webDriver.findElement(By.id("cpf:checkqcetsiretentionperiod")).click();
        webDriver.findElement(By.id("cpf:checkqccustomstring")).click();
        webDriver.findElement(By.id("cpf:textfieldqccustomstringtext")).sendKeys("text");
        CertificateProfileHelper.save(webDriver, true);
    }

    @Test
    public void i_verifyAuditLog() {
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "Certificate Profile Edit", "Success", null,
                Arrays.asList("msg=Edited certificateprofile " + cpName, "useqcstatement=true", "usepkixqcsyntaxv2=true",
                        "useqcstatementraname=text", "useqcsematicsid=text", "useqcetsiqccompliance=true", "useqcetsisignaturedevice=true",
                        "useqcetsivaluelimit=true", "useqcetsiretentionperiod=true", "useqccustomstring=true", "qccustomstringtext=text"));
    }
}
