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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Certificate Profile helper class for EJBCA Web Tests.
 *
 * @version $Id$
 */
public class CertificateProfileHelper extends BaseHelper {

    /**
     * Enum of Approval Settings linking a setting with its index of web elements.
     */
    public enum ApprovalSetting {

        /**
         * Approval Settings / 'Add/Edit End Entity'
         */
        ADD_OR_EDIT_END_ENTITY(0),
        /**
         * Approval Settings / 'Key Recovery'
         */
        KEY_RECOVERY(1),
        /**
         * Approval Settings / 'Revocation'
         */
        REVOCATION(2);

        private final int index;

        ApprovalSetting(final int index) {
            this.index = index;
        }

        /**
         * Returns the setting index.
         *
         * @return the setting index.
         */
        public int getIndex() {
            return index;
        }
    }

    /**
     * Contains constants and references of the 'Certificate Profiles' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editcertificateprofiles/editcertificateprofiles.xhtml";
        static final By PAGE_LINK = By.id("caEditcertificateprofiles");
        // Certificate Profiles Form
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
        /**
         * 'Available Key Algorithms'
         */
        static final By SELECT_KEY_ALGORITHMS = By.id("cpf:selectavailablekeyalgorithms");
        /**
         * 'Available ECDSA curves'
         */
        static final By SELECT_ECDSA_CURVES = By.id("cpf:selectavailableeccurves");
        /**
         * 'Available Bit Lengths'
         */
        static final By SELECT_BIT_LENGTHS = By.id("cpf:selectavailablebitlengths");
        /**
         * 'Signature Algorithm'
         */
        static final By SELECT_SIGNATURE_ALGORITHM = By.id("cpf:selectsignaturealgorithm");
        /**
         * 'Validity or end date of the certificate'
         */
        static final By INPUT_VALIDITY = By.id("cpf:textfieldvalidity");
        /**
         * Permissions / 'Allow Validity Override'
         */
        static final By INPUT_PERMISSIONS_VALIDITY_OVERRIDE = By.id("cpf:checkallowvalidityoverride");
        /**
         * Permissions / 'Allow Extension Override'
         */
        static final By INPUT_PERMISSIONS_EXTENSION_OVERRIDE = By.id("cpf:checkallowextensionoverride");
        /**
         * Permissions / 'Allow Subject DN Override by CSR'
         */
        static final By INPUT_PERMISSIONS_DN_OVERRIDE_BY_CSR = By.id("cpf:checkallowdnoverride");
        /**
         * Permissions / 'Allow Subject DN Override by End Entity Information'
         */
        static final By INPUT_PERMISSIONS_DN_OVERRIDE_BY_END_ENTITY_INFORMATION = By.id("cpf:checkallowdnoverrideeei");
        /**
         * Permissions / 'Allow Key Usage Override'
         */
        static final By INPUT_PERMISSIONS_KEY_USAGE_OVERRIDE = By.id("cpf:checkallowkeyusageoverride");
        /**
         * Permissions / 'Allow Backdated Revocation'
         */
        static final By INPUT_PERMISSIONS_BACKDATED_REVOCATION = By.id("cpf:checkallowbackdatedrevokation");
        /**
         * Permissions / 'Use Certificate Storage'
         */
        static final By INPUT_PERMISSIONS_USE_CERTIFICATE_STORAGE = By.id("cpf:checkUseCertificateStorage");
        /**
         * Permissions / 'Store Certificate Data'
         */
        static final By INPUT_PERMISSIONS_STORE_CERTIFICATE_DATA = By.id("cpf:checkStoreCertificateData");
        /**
         * X.509v3 extensions / 'Basic Constraints' Critical
         */
        static final By INPUT_X509V3_EXTENSIONS_BASIC_CONSTRAINTS_CRITICAL = By.id("cpf:cbbasicconstraintscritical");
        /**
         * X.509v3 extensions / 'Authority Key ID'
         */
        static final By INPUT_X509V3_EXTENSIONS_AUTHORITY_KEY_ID  = By.id("cpf:cbauthoritykeyidentifier");
        /**
         * X.509v3 extensions / 'Subject Key ID'
         */
        static final By INPUT_X509V3_EXTENSIONS_SUBJECT_KEY_ID = By.id("cpf:cbsubjectkeyidentifier");
        /**
         * X.509v3 extensions / Usages / 'Key Usage' Critical
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_CRITICAL = By.id("cpf:cbkeyusagecritical");
        /**
         * X.509v3 extensions / Usages / Key Usage / 'Non-repudiation'
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_NON_REPUDIATION = By.id("cpf:keyUsageNonRepudiation");
        /**
         * X.509v3 extensions / Usages / Key Usage / 'Data encipherment'
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_DATA_ENCIPHERMENT = By.id("cpf:keyUsageDataEncipherment");
        /**
         * X.509v3 extensions / Usages / 'Extended Key Usage' Critical
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_EXTENDED_KEY_USAGE_CRITICAL = By.id("cpf:cbextendedkeyusagecritical");
        /**
         * X.509v3 extensions / Usages / 'Certificate Policies' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USE = By.id("cpf:checkusecertificatepolicies");
        /**
         * X.509v3 extensions / Usages / Certificate Policies / 'Certificate Policy OID'
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CERTIFICATE_POLICY_OID = By.xpath("//input[contains(@id, 'textfieldcertificatepolicyid')]");
        /**
         * X.509v3 extensions / Usages / Certificate Policies / Add
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_ADD = By.xpath("//input[contains(@id, 'buttonaddpolicy')]");
        /**
         * X.509v3 extensions / Usages / Certificate Policies / No Policy Qualifier
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_NO_POLICY_QUALIFIER = By.xpath("//input[contains(@value, 'No Policy Qualifier') and contains(@class, 'selected')]");
        /**
         * X.509v3 extensions / Usages / Certificate Policies / User Notice Text
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USER_NOTICE_TEXT = By.xpath("//input[contains(@value, 'User Notice Text') and contains(@class, 'notSelected')]");
        /**
         * X.509v3 extensions / Usages / Certificate Policies / CPS URI
         */
        static final By INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CPS_URI = By.xpath("//input[contains(@value, 'CPS URI') and contains(@class, 'notSelected')]");

        /**
         * X.509v3 extensions / Names / 'Subject Alternative Name' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_USE = By.id("cpf:cbsubjectalternativename");
        /**
         * X.509v3 extensions / Names / 'Subject Alternative Name' Critical
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_CRITICAL = By.id("cpf:cbsubjectalternativenamecritical");

        /**
         * X.509v3 extensions / Names / 'Issuer Alternative Name' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_USE = By.id("cpf:cbissueralternativename");
        /**
         * X.509v3 extensions / Names / 'Issuer Alternative Name' Critical
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_CRITICAL = By.id("cpf:cbissueralternativenamecritical");
        /**
         * X.509v3 extensions / Names / 'Subject Directory Attributes' Use
         */
        static final By INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_DIRECTORY_ATTRIBUTES = By.id("cpf:checksubjectdirattributes");
        /**
         * X.509v3 extensions / Names / 'Name Constraints' Use
         */
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
        /**
         * Approval Settings / '*'
         */
        static final By SELECT_APPROVAL_SETTINGS_ALL = By.cssSelector("[id$=approvalProfile]");
        // Buttons
        static final By BUTTON_CANCEL_PROFILE = By.id("cpf:cancelEditButton");
        static final By BUTTON_SAVE_PROFILE = By.id("cpf:saveProfileButton");
        // Dynamic references' parts
        static final String TABLE_CERTIFICATE_PROFILES = "//*[@id='editcertificateprofilesForm:editcertificateprofilesTable']";

        // Dynamic references
        static By getCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']");
        }

        static By getViewButtonFromCPTableRowContainingText(final String text) {
            return By.xpath(TABLE_CERTIFICATE_PROFILES + "//tr/td[text()='" + text + "']/following-sibling::td//input[@value='View']");
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
     * Opens the page 'Certificate Profiles' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
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
     * Opens the view page for a Certificate Profile, then asserts that the correct Certificate Profile is being viewed.
     *
     * @param certificateProfileName a Certificate Profile name.
     */
    public void openViewCertificateProfilePage(final String certificateProfileName) {
        // Click edit button for Certificate Profile
        clickLink(Page.getViewButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert correct edit page
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_EDIT_CERTIFICATE_PROFILE, "Certificate Profile: ", certificateProfileName);
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


    /**
     * Fills the validity property ('Validity or end date of the certificate') of the 'Certificate Profile'.
     *
     * @param validityInput validity value.
     */
    public void fillValidity(final String validityInput) {
        fillInput(Page.INPUT_VALIDITY, validityInput);
    }

    /**
     * Selects algorithms ('Available Key Algorithms') and bit lengths ('Available Bit Lengths') of the 'Certificate Profile'.
     *
     * @param selectedAlgorithms key algorithms.
     * @param selectedBitLengths bit lengths.
     */
    public void editCertificateProfile(final List<String> selectedAlgorithms, final List<String> selectedBitLengths) {
        editCertificateProfile(selectedAlgorithms, null, selectedBitLengths, null, null);
    }

    /**
     * Edits the 'Certificate Profile':
     * <ul>
     *     <li>Selects the algorithms by names in the list 'Available Key Algorithms' if not null;</li>
     *     <li>Select the ECDSA curves by name in the list 'Available ECDSA curves' if not null;</li>
     *     <li>Selects the bit lengths by name in the list 'Available Bit Lengths' if not null;</li>
     *     <li>Selects the signature algorithm in the list 'Signature Algorithm' if not null;</li>
     *     <li>Sets the validity in the 'Validity or end date of the certificate' if not null.</li>
     * </ul>
     * @param selectedAlgorithms key algorithms.
     * @param selectedECDSACcurves ECDSA curves.
     * @param selectedBitLengths bit lengths.
     * @param selectedSignatureAlgorithm signature algorithm.
     * @param validityInput validity value.
     */
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
        if (validityInput != null) {
            fillInput(Page.INPUT_VALIDITY, validityInput);
        }
    }

    /**
     * Triggers the input 'Allow Validity Override'.
     */
    public void triggerPermissionsValidityOverride() {
        clickLink(Page.INPUT_PERMISSIONS_VALIDITY_OVERRIDE);
    }

    /**
     * Triggers the input 'Allow Extension Override'.
     */
    public void triggerPermissionsExtensionOverride() {
        clickLink(Page.INPUT_PERMISSIONS_EXTENSION_OVERRIDE);
    }

    /**
     * Triggers the input 'Allow Subject DN Override by CSR'.
     */
    public void triggerPermissionsDnOverrideByCsr() {
        clickLink(Page.INPUT_PERMISSIONS_DN_OVERRIDE_BY_CSR);
    }

    /**
     * Triggers the input 'Allow Subject DN Override by End Entity Information'.
     */
    public void triggerPermissionsDnOverrideByEndEntityInformation() {
        clickLink(Page.INPUT_PERMISSIONS_DN_OVERRIDE_BY_END_ENTITY_INFORMATION);
    }

    /**
     * Triggers the input 'Allow Key Usage Override'.
     */
    public void triggerPermissionsKeyUsageOverride() {
        clickLink(Page.INPUT_PERMISSIONS_KEY_USAGE_OVERRIDE);
    }

    /**
     * Triggers the input 'Allow Backdated Revocation'.
     */
    public void triggerPermissionsBackdatedRevocation() {
        clickLink(Page.INPUT_PERMISSIONS_BACKDATED_REVOCATION);
    }

    /**
     * Triggers the input 'Use Certificate Storage'.
     */
    public void triggerPermissionsUseCertificateStorage() {
        clickLink(Page.INPUT_PERMISSIONS_USE_CERTIFICATE_STORAGE);
    }

    /**
     * Triggers the input 'Store Certificate Data'.
     */
    public void triggerPermissionsStoreCertificateData() {
        clickLink(Page.INPUT_PERMISSIONS_STORE_CERTIFICATE_DATA);
    }

    /**
     * Triggers the input 'Basic Constraints' Critical.
     */
    public void triggerX509v3EextensionsUseBasicConstraintsCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_BASIC_CONSTRAINTS_CRITICAL);
    }

    /**
     * Triggers the input 'Authority Key ID'.
     */
    public void triggerX509v3ExtensionsAuthorityKeyID() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_AUTHORITY_KEY_ID);
    }

    /**
     * Triggers the input 'Subject Key ID'.
     */
    public void triggerX509v3ExtensionsSubjectKeyID() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_SUBJECT_KEY_ID);
    }

    /**
     * Triggers the input 'Key Usage' Critical.
     */
    public void triggerX509v3ExtensionsUsagesKeyUsageCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_CRITICAL);
    }

    /**
     * Triggers the input Key Usage / 'Non-repudiation'.
     */
    public void triggerX509v3ExtensionsUsagesKeyUsageNonRepudiation() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_NON_REPUDIATION);
    }

    /**
     * Triggers the input Key Usage / 'Data encipherment'.
     */
    public void triggerX509v3ExtensionsUsagesKeyUsageDataEncipherment() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_KEY_USAGE_DATA_ENCIPHERMENT);
    }

    /**
     * Triggers the input 'Extended Key Usage' Critical.
     */
    public void triggerX509v3ExtensionsUsagesExtendedKeyUsageCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_EXTENDED_KEY_USAGE_CRITICAL);
    }

    /**
     * Triggers the input 'Certificate Policies' Use.
     */
    public void triggerX509v3ExtensionsUsagesCertificatePoliciesUse() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USE);
    }

    /**
     * Triggers the input 'Subject Alternative Name' Use.
     */
    public void triggerX509v3ExtensionsNamesSubjectAlternativeNameUse() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_USE);
    }

    /**
     * Triggers the input 'Subject Alternative Name' Critical.
     */
    public void triggerX509v3ExtensionsNamesSubjectAlternativeNameCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_ALTERNATIVE_NAME_CRITICAL);
    }

    /**
     * Triggers the input 'Issuer Alternative Name' Use.
     */
    public void triggerX509v3ExtensionsNamesIssuerAlternativeNameUse() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_USE);
    }

    /**
     * Triggers the input 'Issuer Alternative Name' Critical.
     */
    public void triggerX509v3ExtensionsNamesIssuerAlternativeNameCritical() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_ISSUER_ALTERNATIVE_NAME_CRITICAL);
    }

    /**
     * Triggers the input 'Subject Directory Attributes' Use.
     */
    public void triggerX509v3ExtensionsNamesSubjectDirectoryAttributes() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_SUBJECT_DIRECTORY_ATTRIBUTES);
    }

    /**
     * Triggers the input 'Name Constraints' Use.
     */
    public void triggerX509v3ExtensionsNamesNameConstraints() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_NAME_CONSTRAINTS);
    }

    /**
     * Triggers the input 'CRL Distribution Points' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseCrlDistributionPoints() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINTS_USE);
    }

    /**
     * Asserts the element 'Certificate Policy OID' exists.
     */
    public void assertX509v3ExtensionsUsagesCertificatePoliciesCertificatePolicyOidExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CERTIFICATE_POLICY_OID,
                "'Certificate Policy OID' input does not exist."
        );
    }

    /**
     * Asserts the element Certificate Policies / Add exists.
     */
    public void assertX509v3ExtensionsUsagesCertificatePoliciesAddExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_ADD,
                "'Add' input does not exist."
        );
    }

    /**
     * Asserts the element Certificate Policies / No Policy Qualifier exists.
     */
    public void assertX509v3ExtensionsUsagesCertificatePoliciesNPolicyQualifierExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_NO_POLICY_QUALIFIER,
                "'Policy Qualifier' input does not exist."
        );
    }

    /**
     * Asserts the element Certificate Policies / User Notice Text exists.
     */
    public void assertX509v3ExtensionsUsagesCertificatePoliciesUserNoticeTextExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_USER_NOTICE_TEXT,
                "'User Notice Text' input does not exist."
        );
    }

    /**
     * Asserts the element Certificate Policies / CPS URI exists.
     */
    public void assertX509v3ExtensionsUsagesCertificatePoliciesCpsUriExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_USAGES_CERTIFICATE_POLICIES_CPS_URI,
                "'CPS URI' input does not exist."
        );
    }

    /**
     * Asserts the element 'Use CA defined CRL Distribution Point' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPointIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA defined CRL Distribution Point' was not unselected by default",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_DEFINED_CRL_DISTRIBUTION_POINT_USE)
        );
    }

    /**
     * Asserts the element 'CRL Distribution Point URI' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriHasValue(final String value) {
        assertEquals(
                "'CRL Distribution Point URI' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINT_URI)
        );
    }

    /**
     * Asserts the element 'CRL Distribution Point URI' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertX509v3ExtensionsNamesValidationDataCrlDistributionPointUriIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'CRL Distribution Point URI' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_DISTRIBUTION_POINT_URI)
        );
    }

    /**
     * Asserts the element 'CRL Issuer' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataCrlIssuerHasValue(final String value) {
        assertEquals(
                "'CRL Issuer' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_ISSUER)
        );
    }

    /**
     * Asserts the element 'CRL Issuer' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertX509v3ExtensionsNamesValidationDataCrlIssuerIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'CRL Issuer' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CRL_ISSUER)
        );
    }

    /**
     * Triggers the input 'Use CA defined CRL Distribution Point' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedCrlDistributionPoint() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_DEFINED_CRL_DISTRIBUTION_POINT_USE);
    }

    /**
     * Triggers the input 'Freshest CRL (a.k.a. Delta CRL DP)'.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseFreshCrl() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESH_CRL_USE);
    }

    /**
     * Asserts the element 'Use CA Defined Freshest CRL' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA Defined Freshest CRL' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_FRESHEST_CRL_USE)
        );
    }

    /**
     * Asserts the element 'Freshest CRL URI' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataFreshestCrlUriHasValue(final String value) {
        assertEquals(
                "'Freshest CRL URI' had unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESHEST_CRL_URI)
        );
    }

    /**
     * Triggers the input 'Use CA Defined Freshest CRL' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedFreshestCrlUseIsSelected() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_FRESHEST_CRL_USE);
    }

    /**
     * Triggers the input 'Authority Information Access' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseAuthorityInformationAccess() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_AUTHORITY_INFORMATION_ACCESS_USE);
    }

    /**
     * Asserts the element 'Freshest CRL URI' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertX509v3ExtensionsNamesValidationDataFreshestCrlUriIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Freshest CRL URI' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_FRESHEST_CRL_URI)
        );
    }

    /**
     * Asserts the element 'Use CA defined OCSP locator' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocatorIsSelected(final boolean isSelected) {
        assertEquals(
                "'Use CA defined OCSP locator' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_OCSP_LOCATOR)
        );
    }

    /**
     * Asserts the element 'OCSP Service Locator URI' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataOcspServiceLocatorUriHasValue(final String value) {
        assertEquals(
                "'OCSP Service Locator URI' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_OCSP_SERVICE_LOCATOR_URI)
        );
    }

    /**
     * Asserts the element 'CA issuer URI' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataCaIssuerUriHasValue(final String value) {
        assertEquals(
                "'CA issuer URI' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI)
        );
    }

    /**
     * Asserts the element 'CA issuer URI' 'Add' exists.
     */
    public void assertX509v3ExtensionsNamesValidationDataCaIssuerUriAddExists() {
        assertElementExists(
                Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_CA_ISSUER_URI_ADD,
                "'CA issuer URI' 'Add' button is missing."
        );
    }

    /**
     * Triggers the input 'Use CA defined OCSP locator' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataUseCaDefinedOcspLocator() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_USE_CA_DEFINED_OCSP_LOCATOR);
    }

    /**
     * Triggers the input 'Start offset…' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET_USE);
    }

    /**
     * Asserts the element 'Start offset…' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Start offset' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET)
        );
    }

    /**
     * Asserts the element 'Start offset…' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffsetHasValue(final String value) {
        assertEquals(
                "'Start offset' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET)
        );
    }

    /**
     * Sets the value of 'Start offset…'.
     *
     * @param value value.
     */
    public void setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodStartOffset(final String value) {
        fillInput(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_START_OFFSET, value);
    }

    /**
     * Triggers the input 'Period length…' Use.
     */
    public void triggerX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength() {
        clickLink(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH_USE);
    }

    /**
     * Asserts the element 'Period length…' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Period length' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH)
        );
    }

    /**
     * Asserts the element 'Period length…' has value.
     *
     * @param value expected value.
     */
    public void assertX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLengthHasValue(final String value) {
        assertEquals(
                "'Period length' has unexpected default value",
                value,
                getElementValue(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH)
        );
    }

    /**
     * Sets the value of 'Period length…'.
     *
     * @param value value.
     */
    public void setX509v3ExtensionsNamesValidationDataPrivateKeyUsagePeriodPeriodLength(final String value) {
        fillInput(Page.INPUT_X509V3_EXTENSIONS_NAMES_VALIDATION_DATA_PRIVATE_KEY_USAGE_PERIOD_PERIOD_LENGTH, value);
    }

    /**
     * Triggers the input 'Qualified Certificates Statements' Use.
     */
    public void triggerQcStatementsExtensionUseQualifiedCertificatesStatements() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_QUALIFIED_CERTIFICATES_STATEMENTS_USE);
    }

    /**
     * Asserts the element 'PKIX QCSyntax-v2' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionPkixQcSyntaxV2IsSelected(final boolean isSelected) {
        assertEquals(
                "'PKIX QCSyntax-v2' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_PKIX_QCSYNTAXV2_USE)
        );
    }

    /**
     * Asserts the element 'Semantics Identifier (OID)' has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionSemanticsIdentifierOidHasValue(final String value) {
        assertEquals(
                "'Semantics Identifier (OID)' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_SEMANTICS_IDENTIFIER_OID)
        );
    }

    /**
     * Asserts the element 'Name Registration Authorities' has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionNameRegistrationAuthoritiesHasValue(final String value) {
        assertEquals(
                "'Name Registration Authorities' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_NAME_REGISTRATION_AUTHORITIES)
        );
    }

    /**
     * Asserts the element 'ETSI Qualified Certificate compliance' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionEtsiQualifiedCertificateComplianceIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI Qualified Certificate compliance' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_CERTIFICATE_COMPLIANCE_USE)
        );
    }

    /**
     * Asserts the element 'ETSI Qualified Signature/Seal Creation Device' Use is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionEtsiQualifiedSignatureSealCreationDeviceIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI Qualified Signature/Seal Creation Device' Use field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_SIGNATURE_SEAL_CREATION_DEVICE_USE)
        );
    }

    /**
     * Asserts the element 'ETSI transaction value limit' Add is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionEtsiTransactionValueLimitAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI transaction value limit' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_ADD)
        );
    }

    /**
     * Asserts the element 'ETSI transaction value limit' Currency has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionEtsiTransactionValueLimitCurrencyHasValue(final String value) {
        assertEquals(
                "'Currency' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_CURRENCY)
        );
    }

    /**
     * Asserts the element 'ETSI transaction value limit' Amount has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionEtsiTransactionValueLimitAmountHasValue(final String value) {
        assertEquals(
                "'Amount' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_AMOUNT)
        );
    }

    /**
     * Asserts the element 'ETSI transaction value limit' Exponent has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionEtsiTransactionValueLimitExponentHasValue(final String value) {
        assertEquals(
                "'Exponent' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_EXPONENT)
        );
    }

    /**
     * Asserts the element 'ETSI retention period' Add is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionEtsiRetentionPeriodAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'ETSI retention period' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_ADD)
        );
    }

    /**
     * Asserts the element 'ETSI retention period' Value has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionEtsiRetentionPeriodValueHasValue(final String value) {
        assertEquals(
                "'Value (years)' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_VALUE)
        );
    }

    /**
     * Asserts the element 'ETSI type' has selected name.
     *
     * @param name selected name.
     */
    public void assertQcStatementsExtensionEtsiTypeHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_QC_STATEMENTS_EXTENSION_ETSI_TYPE);
        assertNotNull("'ETSI type' was not found", selectedNames);
        assertTrue("'ETSI type' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'ETSI PDS URL / Language' has value.
     *
     * @param value expected value.
     */
    public void assertQcStatementsExtensionEtsiPdsUrlLanguageHasValue(final String value) {
        assertEquals(
                "'ETSI PDS URL' has unexpected default value",
                value,
                getElementValue(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE)
        );
    }

    /**
     * Asserts the element 'ETSI PDS URL / Language' has selected name.
     *
     * @param name selected name.
     */
    public void assertQcStatementsExtensionEtsiPdsUrlLanguageHasSelectedName(final String name) {
        final List<String> selectedNames = getSelectSelectedNames(Page.SELECT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE);
        assertNotNull("'ETSI PDS Language' was not found", selectedNames);
        assertTrue("'ETSI PDS Language' did not have the expected default value", selectedNames.contains(name));
    }

    /**
     * Asserts the element 'ETSI PDS URL / Language' Delete is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertQcStatementsExtensionEtsiPdsUrlLanguageDeleteIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Delete' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_DELETE)
        );
    }

    /**
     * Asserts the element 'ETSI PDS URL / Language' Add Another is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertQcStatementsExtensionEtsiPdsUrlLanguageAddAnotherIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Add Another' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_PDS_URL_LANGUAGE_ADD_ANOTHER)
        );
    }

    /**
     * Asserts the element 'Custom QC-statements String' Add is selected/de-selected.
     *
     * @param isSelected true for selected and false for de-selected.
     */
    public void assertQcStatementsExtensionCustomQcStatementsStringAddIsSelected(final boolean isSelected) {
        assertEquals(
                "'Custom QC-statements String' Add field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_ADD)
        );
    }

    /**
     * Asserts the element 'Custom QC-statements String' Object Identifier (OID) is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertQcStatementsExtensionCustomQcStatementsStringObjectIdentifierIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Object Identifier (OID)' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_OBJECT_IDENTIFIER_OID)
        );
    }

    /**
     * Asserts the element 'Custom QC-statements Text' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertQcStatementsExtensionCustomQcStatementsTextIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Custom QC-statements Text' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_TEXT)
        );
    }

    /**
     * Triggers the input 'PKIX QCSyntax-v2' Use.
     */
    public void triggerQcStatementsExtensionUsePkixQcSyntaxV2() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_PKIX_QCSYNTAXV2_USE);
    }

    /**
     * Sets the value of 'Semantics Identifier (OID)'
     *
     * @param value value.
     */
    public void setQcStatementsExtensionSemanticsIdentifierOid(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_SEMANTICS_IDENTIFIER_OID, value);
    }

    /**
     * Sets the value of 'Name Registration Authorities'
     *
     * @param value value.
     */
    public void setQcStatementsExtensionNameRegistrationAuthorities(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_NAME_REGISTRATION_AUTHORITIES, value);
    }

    /**
     * Triggers the input 'ETSI Qualified Certificate compliance' Use.
     */
    public void triggerQcStatementsExtensionUseEtsiQualifiedCertificateCompliance() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_CERTIFICATE_COMPLIANCE_USE);
    }

    /**
     * Triggers the input 'ETSI Qualified Signature/Seal Creation Device' Use.
     */
    public void triggerQcStatementsExtensionUseEtsiQualifiedSignatureSealCreationDevice() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_QUALIFIED_SIGNATURE_SEAL_CREATION_DEVICE_USE);
    }

    /**
     * Triggers the input 'ETSI transaction value limit' Add.
     */
    public void triggerQcStatementsExtensionAddEtsiTransactionValueLimit() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_ADD);
    }

    /**
     * Sets the value of 'ETSI transaction value limit' Currency
     *
     * @param value value.
     */
    public void setQcStatementsExtensionEtsiTransactionValueLimitCurrency(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_CURRENCY, value);
    }

    /**
     * Sets the value of 'ETSI transaction value limit' Amount
     *
     * @param value value.
     */
    public void setQcStatementsExtensionEtsiTransactionValueLimitAmount(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_AMOUNT, value);
    }

    /**
     * Sets the value of 'ETSI transaction value limit' Exponent
     *
     * @param value value.
     */
    public void setQcStatementsExtensionEtsiTransactionValueLimitExponent(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_TRANSACTION_VALUE_LIMIT_EXPONENT, value);
    }

    /**
     * Triggers the input 'ETSI retention period' Add.
     */
    public void triggerQcStatementsExtensionEtsiRetentionPeriodAdd() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_ETSI_RETENTION_PERIOD_ADD);
    }

    /**
     * Triggers the input 'Custom QC-statements String' Add.
     */
    public void triggerQcStatementsExtensionAddCustomQcStatementsString() {
        clickLink(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_STRING_ADD);
    }

    /**
     * Sets the value of 'Custom QC-statements Text'
     *
     * @param value value.
     */
    public void setQcStatementsExtensionCustomQcStatementsText(final String value) {
        fillInput(Page.INPUT_QC_STATEMENTS_EXTENSION_CUSTOM_QC_STATEMENTS_TEXT, value);
    }

    /**
     * Cancels the edit of the 'Certificate Profile' by clicking cancel button.
     */
    public void cancelEditCertificateProfile() {
        clickLink(Page.BUTTON_CANCEL_PROFILE);
    }

    /**
     * Renames the 'Certificate Profile' and asserts the appearance of renamed profile.
     *
     * @param oldCertificateProfileName current name.
     * @param newCertificateProfileName new name.
     */
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

    /**
     * Clones the 'Certificate Profile' and asserts that both of them old a new exist.
     *
     * @param certificateProfileName source certificate profile name.
     * @param newCertificateProfileName name of the cloned profile.
     */
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

    /**
     * Opens the 'Certificate Profile' deletion dialog.
     *
     * @param certificateProfileName a name of profile for deletion.
     */
    public void deleteCertificateProfile(final String certificateProfileName) {
        // Click 'Delete' button
        clickLink(Page.getDeleteButtonFromCPTableRowContainingText(certificateProfileName));
        // Assert that the correct Certificate Profile is being deleted
        assertCertificateProfileTitleExists(Page.TEXT_TITLE_DELETE_CERTIFICATE_PROFILE, certificateProfileName);
    }

    /**
     * Confirms or discards the deletion of the 'Certificate Profile'.
     *
     * @param isConfirmed true to confirm and false to discard.
     * @param certificateProfileName certificate profile name for assertion.
     */
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

    /**
     * Saves the 'Certificate Profile' and asserts the success.
     */
    public void saveCertificateProfile() {
        clickLink(Page.BUTTON_SAVE_PROFILE);
        assertCertificateProfileSaved();
    }

    /**
     * Asserts the certificate profile name exists in the list.
     *
     * @param certificateProfileName certificate profile name.
     */
    public void assertCertificateProfileNameExists(final String certificateProfileName) {
        assertElementExists(
                Page.getCPTableRowContainingText(certificateProfileName),
                certificateProfileName + " was not found on 'Certificate Profiles' page."
        );
    }

    /**
     * Selects the value by name in the select of Approval Setting by ApprovalSetting type.
     *
     * @param approvalSetting approval setting type.
     * @param name text to select by.
     */
    public void selectApprovalSetting(final ApprovalSetting approvalSetting, final String name) {
        final List<WebElement> approvalSettingElements = getListOfApprovalSettingElements();
        assertApprovalSettingExistsInListOfElements(approvalSettingElements, approvalSetting);
        final WebElement approvalSettingElement = approvalSettingElements.get(approvalSetting.getIndex());
        selectOptionByName(approvalSettingElement, name);
    }

    /**
     * Asserts the name is selected in the select f Approval Setting by ApprovalSetting type.
     *
     * @param approvalSetting approval setting type.
     * @param name selected name.
     */
    public void assertApprovalSettingHasSelectedName(final ApprovalSetting approvalSetting, final String name) {
        final List<WebElement> approvalSettingElements = getListOfApprovalSettingElements();
        assertApprovalSettingExistsInListOfElements(approvalSettingElements, approvalSetting);
        final WebElement approvalSettingElement = approvalSettingElements.get(approvalSetting.getIndex());
        final List<String> approvalSettingSelectedNames = getSelectSelectedNames(approvalSettingElement);
        assertNotNull("Approval Setting [" + approvalSetting.name() + "] was not found.", approvalSettingSelectedNames);
        assertFalse("Approval Setting [" + approvalSetting.name() + "] selection is empty.", approvalSettingSelectedNames.isEmpty());
        assertEquals("Value mismatch for Approval Setting [" + approvalSetting.name() + "].", name, approvalSettingSelectedNames.get(0));
    }

    // Asserts the 'Certificate Profile' name does not exist.
    private void assertCertificateProfileNameDoesNotExists(final String certificateProfileName) {
        assertElementDoesNotExist(
                Page.getCPTableRowContainingText(certificateProfileName),
                certificateProfileName + " was found on 'Certificate Profiles' page."
        );
    }

    // Asserts the 'Certificate Profile' name title exists.
    private void assertCertificateProfileTitleExists(final By textTitleId, final String certificateProfileName) {
        assertCertificateProfileTitleExists(textTitleId, "", certificateProfileName);
    }

    // Asserts the 'Certificate Profile' name title exists.
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

    // Asserts the 'Certificate Profile' save title exists.
    private void assertCertificateProfileSaved() {
        assertInfoMessageAppears("Certificate Profile saved.",
                "Certificate Profile save message was not found.",
                "Expected profile save message was not displayed");
    }

    private List<WebElement> getListOfApprovalSettingElements() {
        final List<WebElement> approvalSettingElements = findElements(Page.SELECT_APPROVAL_SETTINGS_ALL);
        assertNotNull("Cannot find Approval Setting elements.", approvalSettingElements);
        assertFalse("Approval Setting elements are empty.", approvalSettingElements.isEmpty());
        return approvalSettingElements;
    }

    private void assertApprovalSettingExistsInListOfElements(final List<WebElement> elements, final ApprovalSetting approvalSetting) {
        assertFalse("Approval Setting [" + approvalSetting.name() + "] was not found", approvalSetting.getIndex() >= elements.size());
    }

}