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
package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

// TODO JavaDoc
/**
 * Certificate Profile helper class for EJBCA Web Tests.
 *
 * @version $Id: CertificateProfileHelper.java 30035 2018-10-05 08:35:05Z andrey_s_helmes $
 */
public class CertificateProfileHelper extends BaseHelper {

    // TODO Add UI form names to By IDs as JavaDoc to simplify understanding
    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        static final By PAGE_LINK = By.id("caEditcertificateprofiles");
        // Certificate Profiles Form
        static final By TEXT_MESSAGE = By.xpath("//*[@id='messages']//li[@class='infoMessage']");
        static final By INPUT_NAME = By.id("editcertificateprofilesForm:editcertificateprofilesTable:profileNameInputField");
        static final By INPUT_RENAME_NEW_NAME = By.id("editcertificateprofilesForm:renameProfileNew");
        static final By INPUT_CLONE_NEW_NAME = By.id("editcertificateprofilesForm:addFromTemplateProfileNew");
        static final By BUTTON_ADD = By.id("editcertificateprofilesForm:editcertificateprofilesTable:addProfileButton");
        static final By BUTTON_RENAME_CONFIRM = By.id("editcertificateprofilesForm:renameConfirmButton");
        static final By BUTTON_CLONE_CONFIRM = By.id("editcertificateprofilesForm:cloneConfirmButton");
        static final By BUTTON_DELETE_CONFIRM = By.id("editcertificateprofilesForm:deleteConfirmButton");
        static final By BUTTON_DELETE_CANCEL = By.id("editcertificateprofilesForm:deleteCancelButton");
        // Certificate Profile Form
        static final By TEXT_TITLE_EDIT_CERTIFICATE_PROFILE = By.id("titleCertificateProfile");
        static final By TEXT_TITLE_RENAME_CERTIFICATE_PROFILE = By.id("editcertificateprofilesForm:renameProfileOld");
        static final By TEXT_TITLE_CLONE_CERTIFICATE_PROFILE = By.id("editcertificateprofilesForm:addFromTemplateProfileOld");
        static final By TEXT_TITLE_DELETE_CERTIFICATE_PROFILE = By.id("editcertificateprofilesForm:deleteProfileName");
        static final By SELECT_KEY_ALGORITHMS = By.id("cpf:selectavailablekeyalgorithms");
        static final By SELECT_ECDSA_CURVES = By.id("cpf:selectavailableeccurves");
        static final By SELECT_BIT_LENGTHS = By.id("cpf:selectavailablebitlengths");
        static final By SELECT_SIGNATURE_ALGORITHM = By.id("cpf:selectsignaturealgorithm");
        static final By INPUT_VALIDITY = By.id("cpf:textfieldvalidity");
        static final By INPUT_PERMISSIONS_VALIDITY_OVERRIDE = By.id("cpf:checkallowvalidityoverride");
        static final By INPUT_PERMISSIONS_EXTENSION_OVERRIDE = By.id("cpf:checkallowextensionoverride");
        static final By INPUT_PERMISSIONS_DN_OVERRIDE_BY_CSR = By.id("cpf:checkallowdnoverride");
        static final By INPUT_PERMISSIONS_DN_OVERRIDE_BY_END_ENTITY_INFORMATION = By.id("cpf:checkallowdnoverrideeei");
        static final By INPUT_PERMISSIONS_KEY_USAGE_OVERRIDE = By.id("cpf:checkallowkeyusageoverride");
        static final By INPUT_PERMISSIONS_BACKDATED_REVOCATION = By.id("cpf:checkallowbackdatedrevokation");
        static final By INPUT_PERMISSIONS_USE_CERTIFICATE_STORAGE = By.id("cpf:checkUseCertificateStorage");
        static final By INPUT_PERMISSIONS_STORE_CERTIFICATE_DATA = By.id("cpf:checkStoreCertificateData");
        static final By INPUT_X509V3_EXTENSIONS_BASIC_CONSTRAINTS_CRITICAL = By.id("cpf:cbbasicconstraintscritical");
        static final By INPUT_X509V3_EXTENSIONS_AUTHORITY_KEY_ID  = By.id("cpf:cbauthoritykeyidentifier");
        static final By INPUT_X509V3_EXTENSIONS_SUBJECT_KEY_ID = By.id("cpf:cbsubjectkeyidentifier");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_CRITICAL = By.id("cpf:cbkeyusagecritical");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_NON_REPUDIATION = By.id("cpf:keyUsageNonRepudiation");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_DATA_ENCIPHERMENT = By.id("cpf:keyUsageDataEncipherment");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_EXTENDED_KEY_USAGE_CRITICAL = By.id("cpf:cbextendedkeyusagecritical");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USE = By.id("cpf:checkusecertificatepolicies");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CERTIFICATE_POLICY_OID = By.xpath("//input[contains(@id, 'textfieldcertificatepolicyid')]");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_ADD = By.xpath("//input[contains(@id, 'buttonaddpolicy')]");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_NO_POLICY_QUALIFIER = By.xpath("//input[contains(@value, 'No Policy Qualifier') and contains(@class, 'selected')]");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USER_NOTICE_TEXT = By.xpath("//input[contains(@value, 'User Notice Text') and contains(@class, 'notSelected')]");
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CPS_URI = By.xpath("//input[contains(@value, 'CPS URI') and contains(@class, 'notSelected')]");
        static final By INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_CRITICAL = By.id("cpf:cbsubjectalternativenamecritical");
        static final By INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_CRITICAL = By.id("cpf:cbissueralternativenamecritical");
        static final By INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_DIRECTORY_ATTRIBUTES = By.id("cpf:checksubjectdirattributes");
        static final By INPUT_X509V3_EXTENSIONS_NAMES_NAME_CONSTRAINTS = By.id("cpf:checknameconstraints");
        /**
         * X.509v3 extensions / Validation data / 'CRL Distribution Points' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINTS_USE = By.id("cpf:cbcrldistributionpoint");
        /**
         * X.509v3 extensions / Validation data / 'Use CA defined CRL Distribution Point' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_DEFINED_CRL_DISTRIBUTION_POINT_USE = By.id("cpf:cbusedefaultcrldistributionpoint");
        /**
         * X.509v3 extensions / Validation data / 'CRL Distribution Point URI'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINT_URI = By.id("cpf:textfieldcrldisturi");
        /**
         * X.509v3 extensions / Validation data / 'CRL Issuer'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_ISSUER = By.id("cpf:textfieldcrlissuer");
        /**
         * X.509v3 extensions / Validation data / 'Freshest CRL (a.k.a. Delta CRL DP)'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESH_CRL_USE = By.id("cpf:cbusefreshestcrl");
        /**
         * X.509v3 extensions / Validation data / 'Use CA Defined Freshest CRL' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_FRESHEST_CRL_USE = By.id("cpf:cbusecadefinedfreshestcrl");
        /**
         * X.509v3 extensions / Validation data / 'Freshest CRL URI'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESHEST_CRL_URI = By.id("cpf:textfieldfreshestcrluri");
        /**
         * X.509v3 extensions / Validation data / 'Authority Information Access' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_AUTHORITY_INFORMATION_ACCESS_USE = By.id("cpf:checkuseauthorityinformationaccess");
        /**
         * X.509v3 extensions / Validation data / 'Use CA defined OCSP locator' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_OCSP_LOCATOR = By.id("cpf:checkusedefaultocspservicelocator");
        /**
         * X.509v3 extensions / Validation data / 'OCSP Service Locator URI'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_OCSP_SERVICE_LOCATOR_URI = By.id("cpf:textfieldocspservicelocatoruri");
        /**
         * X.509v3 extensions / Validation data / 'CA issuer URI'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI = By.id("cpf:caIssuers:textfieldcaissueruri");
        /**
         * X.509v3 extensions / Validation data / 'CA issuer URI' 'Add'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI_ADD = By.id("cpf:caIssuers:buttonaddcaissueruri");
        /**
         * X.509v3 extensions / Validation data / 'Private Key Usage Period' / 'Start offset…' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET_USE = By.id("cpf:cbuseprivkeyusageperiodnotbefore");
        /**
         * X.509v3 extensions / Validation data / 'Private Key Usage Period' / 'Start offset…'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET = By.id("cpf:textfieldprivkeyusageperiodstartoffset");
        /**
         * X.509v3 extensions / Validation data / 'Private Key Usage Period' / 'Period length…' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH_USE = By.id("cpf:cbuseprivkeyusageperiodnotafter");
        /**
         * X.509v3 extensions / Validation data / 'Private Key Usage Period' / 'Period length…'
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH = By.id("cpf:textfieldprivkeyusageperiodlength");
        /**
         * QC Statements extension / 'Qualified Certificates Statements' Use
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_QUALIFIED_CERTIFICATES_STATEMENTS_USE = By.id("cpf:checkuseqcstatement");
        /**
         * QC Statements extension / 'PKIX QCSyntax-v2' Use
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_PKIX_QCSYNTAXV2_USE = By.id("cpf:checkpkixqcsyntaxv2");
        /**
         * QC Statements extension / 'Semantics Identifier (OID)'
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_SEMANTICS_IDENTIFIER_OID = By.id("cpf:textfieldqcsemanticsid");
        /**
         * QC Statements extension / 'Name Registration Authorities'
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_NAME_REGISTRATION_AUTHORITIES = By.id("cpf:textfieldqcstatementraname");
        /**
         * QC Statements extension / 'ETSI Qualified Certificate compliance' Use
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_CERTIFICATE_COMPLIANCE_USE = By.id("cpf:checkqcetsiqcompliance");
        /**
         * QC Statements extension / 'ETSI Qualified Signature/Seal Creation Device' Use
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_SIGNATURE_SEAL_CREATION_DEVICE_USE = By.id("cpf:checkqcetsisignaturedevice");
        /**
         * QC Statements extension / 'ETSI transaction value limit' Add
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_ADD = By.id("cpf:checkqcetsivaluelimit");
        /**
         * QC Statements extension / 'ETSI transaction value limit' Currency
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_CURRENCY = By.id("cpf:textfieldqcetsivaluelimitcur");
        /**
         * QC Statements extension / 'ETSI transaction value limit' Amount
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_AMOUNT = By.id("cpf:textfieldqcetsivaluelimit");
        /**
         * QC Statements extension / 'ETSI transaction value limit' Exponent
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_EXPONENT = By.id("cpf:textfieldqcetsivaluelimitexp");
        /**
         * QC Statements extension / 'ETSI retention period' Add
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_ADD = By.id("cpf:checkqcetsiretentionperiod");
        /**
         * QC Statements extension / 'ETSI retention period' Value
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_VALUE = By.id("cpf:textfieldqcetsiretentionperiod");
        /**
         * QC Statements extension / 'ETSI type'
         */
        static final By SELECT_QC_STATEMENTS_EXTENSION_ETSI_TYPE = By.id("cpf:qcetsitype");
        /**
         * QC Statements extension / 'ETSI PDS URL / Language'
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE = By.id("cpf:qcetsipdsgroup:0:textfieldqcetsipdsurl");
        /**
         * QC Statements extension / 'ETSI PDS URL / Language'
         */
        static final By SELECT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE = By.id("cpf:qcetsipdsgroup:0:qcetsipdslang");
        /**
         * QC Statements extension / 'ETSI PDS URL / Language' Delete
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_DELETE = By.id("cpf:qcetsipdsgroup:0:buttondeleteqcetsipds");
        /**
         * QC Statements extension / 'ETSI PDS URL / Language' Add Another
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_ADD_ANOTHER = By.id("cpf:qcetsipdsgroup:buttonaddqcetsipds");
        /**
         * QC Statements extension / 'Custom QC-statements String' Add
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_ADD = By.id("cpf:checkqccustomstring");
        /**
         * QC Statements extension / 'Custom QC-statements String' Object Identifier (OID)
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_OBJECT_IDENTIFIER_OID = By.id("cpf:textfieldqccustomstringoid");
        /**
         * QC Statements extension / 'Custom QC-statements Text'
         */
        static final By INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_TEXT = By.id("cpf:textfieldqccustomstringtext");

        static final By BUTTON_CANCEL_PROFILE = By.id("cpf:cancelEditButton");
        static final By BUTTON_SAVE_PROFILE = By.id("cpf:saveProfileButton");

        // Dynamic references' parts
        static final String TABLE_CERTIFICATE_PROFILES = "//*[@id='editcertificateprofilesForm:editcertificateprofilesTable']";

        // Dynamic references
        static By getCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']");
        }

        static By getEditButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Edit']");
        }

        static By getDeleteButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Delete']");
        }

        static By getRenameButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Rename']");
        }

        static By getCloneButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='Clone']");
        }
    }

    public CertificateProfileHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'Certificate Profiles' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a new Certificate Profile, and asserts that it appears in Certificate Profiles table.
     *
     * @param certificateProfileName a Certificate Profile name.
     */
    public void addCertificateProfile(final String certificateProfileName) {
        fillInput(Page.INPUT_NAME, certificateProfileName);
        clickLink(Page.BUTTON_ADD);
        // Assert Certificate Profile exists
        assertCertificateProfileNameExists(certificateProfileName);
    }

    /**
     * Opens the edit page for a Certificate Profile, then asserts that the correct Certificate Profile is being edited.
     *
     * @param certificateProfileName a Certificate Profile name.
     */
    public void openEditCertificateProfilePage(final String certificateProfileName) {
        // Click edit button for Certificate Profile
        clickLink(Page.getEditButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert correct edit page
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_EDIT_CERTIFICATE_PROFILE, "Certificate Profile: ", certificateProfileName);
    }

    public void editCertificateProfile(final String validityInput) {
        editCertificateProfile(null, null, null, null, validityInput);
    }

    public void editCertificateProfile(final List<String> selectedAlgorithms, final List<String> selectedBitLengths) {
        editCertificateProfile(selectedAlgorithms, null, selectedBitLengths, null, null);
    }

    // TODO: In case of growing number of parameters for this method -> introduce DTO to edit certificate profile
    public void editCertificateProfile(
            final List<String> selectedAlgorithms,
            final List<String> selectedECDSACcurves,
            final List<String> selectedBitLengths,
            final String selectedSignatureAlgorithm,
            final String validityInput) {
        if(selectedAlgorithms != null) {
            selectOptionsByName(Page.SELECT_KEY_ALGORITHMS, selectedAlgorithms);
        }
        if(selectedECDSACcurves != null) {
            selectOptionsByName(Page.SELECT_ECDSA_CURVES, selectedECDSACcurves);
        }
        if(selectedBitLengths != null) {
            selectOptionsByName(Page.SELECT_BIT_LENGTHS, selectedBitLengths);
        }
        if(selectedSignatureAlgorithm != null) {
            selectOptionByName(Page.SELECT_SIGNATURE_ALGORITHM, selectedSignatureAlgorithm);
        }
        if(validityInput != null) {
            fillInput(Page.INPUT_VALIDITY, validityInput);
        }
    }

    public void triggerPermissionsValidityOverride() {
        clickLink(Page.INPUT_PERMISSIONS_VALIDITY_OVERRIDE);
    }

    public void triggerPermissionsExtensionOverride() {
        clickLink(Page.INPUT_PERMISSIONS_EXTENSION_OVERRIDE);
    }

    public void triggerPermissionsDnOverrideByCsr() {
        clickLink(Page.INPUT_PERMISSIONS_DN_OVERRIDE_BY_CSR);
    }

    public void triggerPermissionsDnOverrideByEndEntityInformation() {
        clickLink(Page.INPUT_PERMISSIONS_DN_OVERRIDE_BY_END_ENTITY_INFORMATION);
    }

    public void triggerPermissionsKeyUsageOverride() {
        clickLink(Page.INPUT_PERMISSIONS_KEY_USAGE_OVERRIDE);
    }

    public void triggerPermissionsBackdatedRevocation() {
        clickLink(Page.INPUT_PERMISSIONS_BACKDATED_REVOCATION);
    }

    public void triggerPermissionsUseCertificateStorage() {
        clickLink(Page.INPUT_PERMISSIONS_USE_CERTIFICATE_STORAGE);
    }

    public void triggerPermissionsStoreCertificateData() {
        clickLink(Page.INPUT_PERMISSIONS_STORE_CERTIFICATE_DATA);
    }

    public void triggerX509v3EextensionsUseBasicConstraintsCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_BASIC_CONSTRAINTS_CRITICAL);
    }

    public void triggerX509v3ExtensionsAuthorityKeyID() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_AUTHORITY_KEY_ID);
    }

    public void triggerX509v3ExtensionsSubjectKeyID() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_SUBJECT_KEY_ID);
    }

    public void triggerX509v3ExtensionsUsagesKeyUsageCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_CRITICAL);
    }

    public void triggerX509v3ExtensionsUsagesKeyUsageNonRepudiation() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_NON_REPUDIATION);
    }

    public void triggerX509v3ExtensionsUsagesKeyUsageDataEncipherment() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_DATA_ENCIPHERMENT);
    }

    public void triggerX509v3ExtensionsUsagesExtendedKeyUsageCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_EXTENDED_KEY_USAGE_CRITICAL);
    }

    public void triggerX509v3ExtensionsUsagesCertificatePoliciesUse() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USE);
    }

    public void triggerX509v3ExtensionsNamesSubjectAlternativeNameCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_CRITICAL);
    }

    public void triggerX509v3ExtensionsNamesIssuerAlternativeNameCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_CRITICAL);
    }

    public void triggerX509v3ExtensionsNamesSubjectDirectoryAttributes() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_DIRECTORY_ATTRIBUTES);
    }

    public void triggerX509v3ExtensionsNamesNameConstraints() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_NAME_CONSTRAINTS);
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseCrlDistributionPoints() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINTS_USE);
    }

    public void assertX509v3ExtensionsUsagesCertificatePoliciesCertificatePolicyOidExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CERTIFICATE_POLICY_OID,
                "'Certificate Policy OID' input does not exist."
        );
    }

    public void assertX509v3ExtensionsUsagesCertificatePoliciesAddExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_ADD,
                "'Add' input does not exist."
        );
    }

    public void assertX509v3ExtensionsUsagesCertificatePoliciesNPolicyQualifierExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_NO_POLICY_QUALIFIER,
                "'Policy Qualifier' input does not exist."
        );
    }

    public void assertX509v3ExtensionsUsagesCertificatePoliciesUserNoticeTextExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USER_NOTICE_TEXT,
                "'User Notice Text' input does not exist."
        );
    }

    public void assertX509v3ExtensionsUsagesCertificatePoliciesCpsUriExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CPS_URI,
                "'CPS URI' input does not exist."
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPointIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA defined CRL Distribution Point' was not unselected by default",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_DEFINED_CRL_DISTRIBUTION_POINT_USE)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriHasValue(final String value) {
        assertEquals(
                "'CRL Distribution Point URI' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINT_URI)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'CRL Distribution Point URI' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINT_URI)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCrlIssuerHasValue(final String value) {
        assertEquals(
                "'CRL Issuer' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_ISSUER)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCrlIssuerIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'CRL Issuer' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_ISSUER)
        );
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPoint() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_DEFINED_CRL_DISTRIBUTION_POINT_USE);
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseFreshCrl() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESH_CRL_USE);
    }

    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA Defined Freshest CRL' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_FRESHEST_CRL_USE)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataFreshestCrlUriHasValue(final String value) {
        assertEquals(
                "'Freshest CRL URI' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESHEST_CRL_URI)
        );
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_FRESHEST_CRL_USE);
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseAuthorityInformationAccess() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_AUTHORITY_INFORMATION_ACCESS_USE);
    }

    public void assertX509v3ExtensionsNamesValidationDataFreshestCrlUriIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Freshest CRL URI' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESHEST_CRL_URI)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocatorIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA defined OCSP locator' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_OCSP_LOCATOR)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataOcspServiceLocatorUriHasValue(final String value) {
        assertEquals(
                "'OCSP Service Locator URI' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_OCSP_SERVICE_LOCATOR_URI)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCaIssuerUriHasValue(final String value) {
        assertEquals(
                "'CA issuer URI' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataCaIssuerUriAddExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI_ADD,
                "'CA issuer URI' 'Add' button is missing."
        );
    }

    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocator() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_OCSP_LOCATOR);
    }

    public void triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET_USE);
    }

    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Start offset' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetHasValue(final String value) {
        assertEquals(
                "'Start offset' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET)
        );
    }

    public void setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset(final String value) {
        fillInput(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET, value);
    }

    public void triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH_USE);
    }

    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Period length' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH)
        );
    }

    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthHasValue(final String value) {
        assertEquals(
                "'Period length' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH)
        );
    }

    public void setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength(final String value) {
        fillInput(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH, value);
    }

    public void triggerQcStatementsExtensionUseQualifiedCertificatesStatements() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_QUALIFIED_CERTIFICATES_STATEMENTS_USE);
    }

    public void assertQcStatementsExtensionPkixQcSyntaxV2IsSelected(final boolean isSelected) {
        assertEquals(
                "'PKIX QCSyntax-v2' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_PKIX_QCSYNTAXV2_USE)
        );
    }

    public void assertQcStatementsExtensionSemanticsIdentifierOidHasValue(final String value) {
        assertEquals(
                "'Semantics Identifier (OID)' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_SEMANTICS_IDENTIFIER_OID)
        );
    }

    public void assertQcStatementsExtensionNameRegistrationAuthoritiesHasValue(final String value) {
        assertEquals(
                "'Name Registration Authorities' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_NAME_REGISTRATION_AUTHORITIES)
        );
    }

    public void assertQcStatementsExtensionEtsiQualifiedCertificateComplianceIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI Qualified Certificate compliance' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_CERTIFICATE_COMPLIANCE_USE)
        );
    }

    public void assertQcStatementsExtensionEtsiQualifiedSignatureSealCreationDeviceIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI Qualified Signature/Seal Creation Device' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_SIGNATURE_SEAL_CREATION_DEVICE_USE)
        );
    }

    public void assertQcStatementsExtensionEtsiTransactionValueLimitAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI transaction value limit' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_ADD)
        );
    }

    public void assertQcStatementsExtensionEtsiTransactionValueLimitCurrencyHasValue(final String value) {
        assertEquals(
                "'Currency' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_CURRENCY)
        );
    }

    public void assertQcStatementsExtensionEtsiTransactionValueLimitAmountHasValue(final String value) {
        assertEquals(
                "'Amount' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_AMOUNT)
        );
    }

    public void assertQcStatementsExtensionEtsiTransactionValueLimitExponentHasValue(final String value) {
        assertEquals(
                "'Exponent' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_EXPONENT)
        );
    }

    public void assertQcStatementsExtensionEtsiRetentionPeriodAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI retention period' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_ADD)
        );
    }

    public void assertQcStatementsExtensionEtsiRetentionPeriodValueHasValue(final String value) {
        assertEquals(
                "'Value (years)' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_VALUE)
        );
    }

    public void assertQcStatementsExtensionEtsiTypeHasSelectedValue(final String value) {
        final List<String> selectedNames = getSelectSelectedValues(Page.SELECT_QC_STATEMENTS_EXTENSION_ETSI_TYPE);
        assertNotNull("'ETSI type' was not found", selectedNames);
        assertTrue("'ETSI type' did not have the expected default value", selectedNames.contains(value));
    }

    public void assertQcStatementsExtensionEtsiPdsUrlLanguageHasValue(final String value) {
        assertEquals(
                "'ETSI PDS URL' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE)
        );
    }

    public void assertQcStatementsExtensionEtsiPdsUrlLanguageHasSelectedValue(final String value) {
        final List<String> selectedNames = getSelectSelectedValues(Page.SELECT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE);
        assertNotNull("'ETSI PDS Language' was not found", selectedNames);
        assertTrue("'ETSI PDS Language' did not have the expected default value", selectedNames.contains(value));
    }

    public void assertQcStatementsExtensionEtsiPdsUrlLanguageDeleteIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Delete' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_DELETE)
        );
    }

    public void assertQcStatementsExtensionEtsiPdsUrlLanguageAddAnotherIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Add Another' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_ADD_ANOTHER)
        );
    }

    public void assertQcStatementsExtensionCustomQcStatementsStringAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'Custom QC-statements String' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_ADD)
        );
    }

    public void assertQcStatementsExtensionCustomQcStatementsStringObjectIdentifierIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Object Identifier (OID)' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_OBJECT_IDENTIFIER_OID)
        );
    }

    public void assertQcStatementsExtensionCustomQcStatementsTextIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Custom QC-statements Text' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_TEXT)
        );
    }

    public void triggerQcStatementsExtensionUsePkixQcSyntaxV2() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_PKIX_QCSYNTAXV2_USE);
    }

    public void setQcStatementsExtensionSemanticsIdentifierOid(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_SEMANTICS_IDENTIFIER_OID, value);
    }

    public void setQcStatementsExtensionNameRegistrationAuthorities(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_NAME_REGISTRATION_AUTHORITIES, value);
    }

    public void triggerQcStatementsExtensionUseEtsiQualifiedCertificateCompliance() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_CERTIFICATE_COMPLIANCE_USE);
    }

    public void triggerQcStatementsExtensionUseEtsiQualifiedSignatureSealCreationDevice() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_SIGNATURE_SEAL_CREATION_DEVICE_USE);
    }

    public void triggerQcStatementsExtensionAddEtsiTransactionValueLimit() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_ADD);
    }

    public void setQcStatementsExtensionEtsiTransactionValueLimitCurrency(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_CURRENCY, value);
    }

    public void setQcStatementsExtensionEtsiTransactionValueLimitAmount(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_AMOUNT, value);
    }

    public void setQcStatementsExtensionEtsiTransactionValueLimitExponent(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_EXPONENT, value);
    }

    public void triggerQcStatementsExtensionEtsiRetentionPeriodAdd() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_ADD);
    }

    public void triggerQcStatementsExtensionAddCustomQcStatementsString() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_ADD);
    }

    public void setQcStatementsExtensionCustomQcStatementsText(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_TEXT, value);
    }

    public void cancelEditCertificateProfile() {
        clickLink(Page.BUTTON_CANCEL_PROFILE);
    }

    public void renameCertificateProfile(final String oldCertificateProfileName, final String newCertificateProfileName) {
        // Click 'Rename' button
        clickLink(Page.getRenameButtonFromCPTableRowContainingText(oldCertificateProfileName));
        // Assert that the correct Certificate Profile is being renamed
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_RENAME_CERTIFICATE_PROFILE, oldCertificateProfileName);
        // Enter new name for Certificate Profile
        fillInput(Page.INPUT_RENAME_NEW_NAME, newCertificateProfileName);
        // Rename Certificate Profile
        clickLink(Page.BUTTON_RENAME_CONFIRM);
        // Assert Certificate Profile exists
        assertCertificateProfileNameExists(newCertificateProfileName);
    }

    public void cloneCertificateProfile(final String certificateProfileName, final String newCertificateProfileName) {
        // Click 'Clone' button
        clickLink(Page.getCloneButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert that the correct Certificate Profile is being cloned
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_CLONE_CERTIFICATE_PROFILE, certificateProfileName);
        // Enter name for new Certificate Profile
        fillInput(Page.INPUT_CLONE_NEW_NAME, newCertificateProfileName);
        // Clone Certificate Profile
        clickLink(Page.BUTTON_CLONE_CONFIRM);
        // Assert Certificate Profiles exist
        assertCertificateProfileNameExists(certificateProfileName);
        assertCertificateProfileNameExists(newCertificateProfileName);
    }

    public void deleteCertificateProfile(final String certificateProfileName) {
        // Click 'Delete' button
        clickLink(Page.getDeleteButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert that the correct Certificate Profile is being deleted
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_DELETE_CERTIFICATE_PROFILE, certificateProfileName);
    }

    public void confirmCertificateProfileDeletion(final boolean isConfirmed, final String certificateProfileName) {
        if (isConfirmed) {
            // Delete and assert deletion
            clickLink(Page.BUTTON_DELETE_CONFIRM);
            // Assert Certificate Profile does not exist
            assertCertificateProfileNameDoesNotExists(certificateProfileName);
        } else {
            // Cancel deletion and assert Certificate Profile still exists
            clickLink(Page.BUTTON_DELETE_CANCEL);
            // Assert Certificate Profile exists
            assertCertificateProfileNameExists(certificateProfileName);
        }
    }

    public void saveCertificateProfile() {
        clickLink(Page.BUTTON_SAVE_PROFILE);
        assertCertificateProfileSaved();
    }

    private void assertCertificateProfileNameExists(final String certificateProfileName) {
        assertElementExists(
                Page.getCPTableRowContainingText(certificateProfileName),
                certificateProfileName + " was not found on 'Certificate Profiles' page."
        );
    }

    private void assertCertificateProfileNameDoesNotExists(final String certificateProfileName) {
        assertElementDoesNotExist(
                Page.getCPTableRowContainingText(certificateProfileName),
                certificateProfileName + " was found on 'Certificate Profiles' page."
        );
    }

    private void assertCertificateProfileTitleExists(final By textTitleId, final String certificateProfileName) {
        assertCertificateProfileTitleExists(textTitleId, "", certificateProfileName);
    }

    private void assertCertificateProfileTitleExists(final By textTitleId, final String prefixString, final String certificateProfileName) {
        final WebElement certificateProfileTitle = findElement(textTitleId);
        if(certificateProfileName == null) {
            fail("Certificate Profile title was not found.");
        }
        assertEquals(
                "Action on wrong Certificate Profile.",
                prefixString + certificateProfileName,
                certificateProfileTitle.getText()
        );
    }

    private void assertCertificateProfileSaved() {
        final WebElement certificateProfileSaveMessage = findElement(Page.TEXT_MESSAGE);
        if(certificateProfileSaveMessage == null) {
            fail("Certificate Profile save message was not found.");
        }
        assertEquals(
                "Expected profile save message was not displayed",
                "Certificate Profile saved.",
                certificateProfileSaveMessage.getText()
        );
    }

}