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

import java.util.Arrays;
import java.util.Collections;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CertificateProfileHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

// TODO Check stepA_add_CertificateProfile as we have 1:1 duplicate in org.ejbca.webtest.scenario.EcaQa12_CPManagement.stepA_add_CertificateProfile()
/**
 * Verifies that changes made to Certificate Profiles in the AdminWeb propagates to the backend.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-74">ECAQA-74</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa74_CpBackend extends WebTestBase {

    // Helpers
    private static AuditLogHelper auditLogHelper;
    private static CertificateProfileHelper certificateProfileHelper;
    // Test Data
    public static class TestData {
        static final String CERTIFICATE_PROFILE_NAME = "ECAQA-74-CertificateProfile";
    }


    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        final WebDriver webDriver = getWebDriver();
        // Init helpers
        certificateProfileHelper = new CertificateProfileHelper(webDriver);
        auditLogHelper = new AuditLogHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCertificateProfileByName(TestData.CERTIFICATE_PROFILE_NAME);
        // super
        afterClass();
    }

    @Test
    public void stepA_add_CertificateProfile() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        // Add Certificate Profile
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.addCertificateProfile(TestData.CERTIFICATE_PROFILE_NAME);
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Create",
                "Success",
                null,
                Collections.singletonList("New certificate profile " + TestData.CERTIFICATE_PROFILE_NAME + " added successfully.")
        );
    }

    @Test
    public void stepB_overrideOptions() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Set 'Available Key Algorithms', 'Available ECDSA curves', 'Available Bit Lengths' and 'Signature Algorithm'
        certificateProfileHelper.editCertificateProfile(
                Arrays.asList("ECDSA", "RSA"),
                Collections.singletonList("prime256v1 / secp256r1 / P-256"),
                Arrays.asList("2048 bits", "3072 bits", "4096 bits"),
                "SHA256WithRSA",
                "365d"
        );
        // Clicky stuff
        certificateProfileHelper.triggerPermissionsValidityOverride();
        certificateProfileHelper.triggerPermissionsExtensionOverride();
        certificateProfileHelper.triggerPermissionsDnOverrideByCsr();
        certificateProfileHelper.triggerPermissionsDnOverrideByEndEntityInformation();
        certificateProfileHelper.triggerPermissionsKeyUsageOverride();
        certificateProfileHelper.triggerPermissionsBackdatedRevocation();
        certificateProfileHelper.triggerPermissionsUseCertificateStorage();
        certificateProfileHelper.triggerPermissionsStoreCertificateData();
        // Save updated profile
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME,
                        "encodedvalidity=1y",
                        "allowvalidityoverride=true",
                        "allowextensionoverride=true",
                        "allowdnoverride=true",
                        "allowdnoverridebyeei=true",
                        "allowbackdatedrevokation=true",
                        "usecertificatestorage=false",
                        "storecertificatedata=false",
                        "availablekeyalgorithms=[ECDSA, RSA]",
                        "availableeccurves=[prime256v1]",
                        "availablebitlengths=[2048, 3072, 4096]",
                        "minimumavailablebitlength=2048",
                        "maximumavailablebitlength=4096",
                        "signaturealgorithm=SHA256WithRSA",
                        "allowkeyusageoverride=true")
        );
    }

    @Test
    public void stepC_certificatePoliciesOptions() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // More clicky stuff
        certificateProfileHelper.triggerX509v3EextensionsUseBasicConstraintsCritical();
        certificateProfileHelper.triggerX509v3ExtensionsAuthorityKeyID();
        certificateProfileHelper.triggerX509v3ExtensionsSubjectKeyID();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesKeyUsageCritical();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesKeyUsageNonRepudiation();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesKeyUsageDataEncipherment();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesExtendedKeyUsageCritical();
        certificateProfileHelper.triggerX509v3ExtensionsUsagesCertificatePoliciesUse();
        // Check that new fields appeared
        certificateProfileHelper.assertX509v3ExtensionsUsagesCertificatePoliciesCertificatePolicyOidExists();
        certificateProfileHelper.assertX509v3ExtensionsUsagesCertificatePoliciesAddExists();
        certificateProfileHelper.assertX509v3ExtensionsUsagesCertificatePoliciesNPolicyQualifierExists();
        certificateProfileHelper.assertX509v3ExtensionsUsagesCertificatePoliciesUserNoticeTextExists();
        certificateProfileHelper.assertX509v3ExtensionsUsagesCertificatePoliciesCpsUriExists();
        // Save
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME,
                        "basicconstraintscritical=false",
                        "usesubjectkeyidentifier=false",
                        "useauthoritykeyidentifier=false",
                        "usecertificatepolicies=true",
                        "keyusage=[true, false, true, true, false, false, false, false, false]",
                        "keyusagecritical=false",
                        "extendedkeyusagecritical=true"
                )
        );
    }

    @Test
    public void stepD_crlDistributionPointsEnable() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // More clicky stuff
        certificateProfileHelper.triggerX509v3ExtensionsNamesSubjectAlternativeNameCritical();
        certificateProfileHelper.triggerX509v3ExtensionsNamesIssuerAlternativeNameCritical();
        certificateProfileHelper.triggerX509v3ExtensionsNamesSubjectDirectoryAttributes();
        certificateProfileHelper.triggerX509v3ExtensionsNamesNameConstraints();
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCrlDistributionPoints();
        // Check that new fields appeared
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPointIsSelected(false);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriHasValue(
                getPublicWebUrl() + "publicweb/webdist/certdist?cmd=crl&issuer=CN=TestCA,O=AnaTom,C=SE"
        );
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCrlIssuerHasValue("CN=TestCA,O=AnaTom,C=SE");
        // Save
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME,
                        "subjectalternativenamecritical=true",
                        "issueralternativenamecritical=true",
                        "usecrldistributionpoint=true",
                        "crldistributionpointuri=" + getPublicWebUrl() +"publicweb/webdist/certdist?cmd=crl&issuer=CN=TestCA,O=AnaTom,C=SE",
                        "crlissuer=CN=TestCA,O=AnaTom,C=SE",
                        "usesubjectdirattributes=true",
                        "usenameconstraints=true",
                        "nameconstraintscritical=false"
                )
        );
    }

    @Test
    public void stepE_crlDistributionPointsOptions() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Enable 'Use CA defined CRL Distribution Point' and check that fields become disabled
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPoint();
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriIsEnabled(false);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCrlIssuerIsEnabled(false);
        // Enable 'Freshest CRL' and check that new fields appeared
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseFreshCrl();
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected(false);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataFreshestCrlUriHasValue(
                getPublicWebUrl() + "publicweb/webdist/certdist?cmd=deltacrl&issuer=CN=TestCA,O=AnaTom,C=SE"
        );
        // Enable 'Use CA Defined Freshest CRL' and 'Authority Information Access' and check that fields appear/are disabled
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected();
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseAuthorityInformationAccess();
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataFreshestCrlUriIsEnabled(false);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocatorIsSelected(false);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataOcspServiceLocatorUriHasValue("");
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCaIssuerUriHasValue("");
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataCaIssuerUriAddExists();
        // Enable 'Use CA defined OCSP locator'
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocator();
        // Enable 'Private Key Usage Period' and check that new fields become enabled
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset();
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetIsEnabled(true);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetHasValue("0d");
        // Set 'Start offset'
        certificateProfileHelper.setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset("1d");
        // Enable 'Period length' and check that new fields become enabled
        certificateProfileHelper.triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength();
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthIsEnabled(true);
        certificateProfileHelper.assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthHasValue("2y");
        // Set 'Period length'
        certificateProfileHelper.setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength("360d");
        // Save
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME,
                        "usedefaultcrldistributionpoint=true",
                        "crldistributionpointuri=",
                        "usefreshestcrl=true",
                        "usecadefinedfreshestcrl=true",
                        "crlissuer=",
                        "useauthorityinformationaccess=true",
                        "usedefaultocspservicelocator=true",
                        "useprivkeyusageperiodnotbefore=true",
                        "useprivkeyusageperiod=true",
                        "useprivkeyusageperiodnotafter=true",
                        "privkeyusageperiodstartoffset=86400",
                        "privkeyusageperiodlength=31104000"
                )
        );
    }

    @Test
    public void stepF_qcStatementsEnable() {
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Enable 'Qualified Certificates Statements' and check that new fields appear
        certificateProfileHelper.triggerQcStatementsExtensionUseQualifiedCertificatesStatements();
        certificateProfileHelper.assertQcStatementsExtensionPkixQcSyntaxV2IsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionSemanticsIdentifierOidHasValue("");
        certificateProfileHelper.assertQcStatementsExtensionNameRegistrationAuthoritiesHasValue("");
        certificateProfileHelper.assertQcStatementsExtensionEtsiQualifiedCertificateComplianceIsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionEtsiQualifiedSignatureSealCreationDeviceIsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionEtsiTransactionValueLimitAddIsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionEtsiTransactionValueLimitCurrencyHasValue("");
        certificateProfileHelper.assertQcStatementsExtensionEtsiTransactionValueLimitAmountHasValue("0");
        certificateProfileHelper.assertQcStatementsExtensionEtsiTransactionValueLimitExponentHasValue("0");
        certificateProfileHelper.assertQcStatementsExtensionEtsiRetentionPeriodAddIsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionEtsiRetentionPeriodValueHasValue("0");
        certificateProfileHelper.assertQcStatementsExtensionEtsiTypeHasSelectedName("Unused");
        certificateProfileHelper.assertQcStatementsExtensionEtsiPdsUrlLanguageHasValue("");
        certificateProfileHelper.assertQcStatementsExtensionEtsiPdsUrlLanguageHasSelectedName("English");
        certificateProfileHelper.assertQcStatementsExtensionEtsiPdsUrlLanguageDeleteIsEnabled(false);
        certificateProfileHelper.assertQcStatementsExtensionEtsiPdsUrlLanguageAddAnotherIsEnabled(true);
        certificateProfileHelper.assertQcStatementsExtensionCustomQcStatementsStringAddIsSelected(false);
        certificateProfileHelper.assertQcStatementsExtensionCustomQcStatementsStringObjectIdentifierIsEnabled(false);
        certificateProfileHelper.assertQcStatementsExtensionCustomQcStatementsTextIsEnabled(false);
        // Push cancel to discard changes
        certificateProfileHelper.cancelEditCertificateProfile();
    }

    @Test
    public void stepG_qcStatementsEdit() {
        // Update default timestamp
        auditLogHelper.initFilterTime();
        certificateProfileHelper.openPage(getAdminWebUrl());
        certificateProfileHelper.openEditCertificateProfilePage(TestData.CERTIFICATE_PROFILE_NAME);
        // Click boxes and fill text fields
        certificateProfileHelper.triggerQcStatementsExtensionUseQualifiedCertificatesStatements();
        certificateProfileHelper.triggerQcStatementsExtensionUsePkixQcSyntaxV2();
        certificateProfileHelper.setQcStatementsExtensionSemanticsIdentifierOid("text");
        certificateProfileHelper.setQcStatementsExtensionNameRegistrationAuthorities("text");
        certificateProfileHelper.triggerQcStatementsExtensionUseEtsiQualifiedCertificateCompliance();
        certificateProfileHelper.triggerQcStatementsExtensionUseEtsiQualifiedSignatureSealCreationDevice();
        certificateProfileHelper.triggerQcStatementsExtensionAddEtsiTransactionValueLimit();
        certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitCurrency("");
        certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitAmount("1");
        certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitExponent("3");
        certificateProfileHelper.triggerQcStatementsExtensionEtsiRetentionPeriodAdd();
        certificateProfileHelper.triggerQcStatementsExtensionAddCustomQcStatementsString();
        certificateProfileHelper.setQcStatementsExtensionCustomQcStatementsText("text");
        // Save
        certificateProfileHelper.saveCertificateProfile();
        // Verify Audit Log
        auditLogHelper.openPage(getAdminWebUrl());
        auditLogHelper.assertLogEntryByEventText(
                "Certificate Profile Edit",
                "Success",
                null,
                Arrays.asList(
                        "msg=Edited certificateprofile " + TestData.CERTIFICATE_PROFILE_NAME,
                        "useqcstatement=true",
                        "usepkixqcsyntaxv2=true",
                        "useqcstatementraname=text",
                        "useqcsematicsid=text",
                        "useqcetsiqccompliance=true",
                        "useqcetsisignaturedevice=true",
                        "useqcetsivaluelimit=true",
                        "useqcetsiretentionperiod=true",
                        "useqccustomstring=true",
                        "qccustomstringtext=text"
                )
        );
    }

    /*
    TODO Extract validation check into separate test case
    certificateProfileHelper.triggerQcStatementsExtensionUseQualifiedCertificatesStatements();
    certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitCurrency("text");
    certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitAmount("text");
    certificateProfileHelper.setQcStatementsExtensionEtsiTransactionValueLimitExponent("text");
    // Save
    certificateProfileHelper.saveCertificateProfile();
    // Check that two errors appear
    // TODO No longer immediately validated after JSP -> JSF leap (though on save)
    WebElement messages = webDriver.findElement(By.id("messages"));
    List<WebElement> errorMessages = messages.findElements(By.xpath(".//li"));
    for (WebElement message : errorMessages) {
        assertEquals("Only decimal numbers are allowed in ETSI Value Limit Amount and Exponent fields.", message.getText());
    }
    assertEquals("Expected 2 error messages", 2, errorMessages.size());
    */
}
