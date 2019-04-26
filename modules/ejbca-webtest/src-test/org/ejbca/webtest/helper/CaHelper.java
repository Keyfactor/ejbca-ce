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

import java.util.List;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * 'Certificate Authorities' helper class for EJBCA Web Tests.
 *
 * @version $Id$
 */
public class CaHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'CA' page.
     */
    public static class Page {
        // General
        static final String PAGE_URI = "/ejbca/adminweb/ca/editcas/managecas.xhtml";
        static final By PAGE_LINK = By.id("caEditcas");

        // Buttons
        //Manage CAs
        static final By BUTTON_CREATE_CA = By.id("managecas:buttoncreateca");
        static final By BUTTON_EDIT = By.id("managecas:buttoneditca");
        static final By BUTTON_DELETE_CA = By.id("managecas:buttondeleteca");
        //Edit CAs
        static final By BUTTON_CREATE = By.id("editcapage:buttoncreate");
        static final By BUTTON_SAVE = By.id("editcapage:buttonsave");
        static final By BUTTON_SAVE_INITIALIZE = By.id("editcapage:buttoninitialize");;

        //CRL Points
        /**
         * Generate Default CRL Distribution Point
         */
        static final By BUTTON_GENERATEDEFAULTCRLDISTRIBUTIONPOINT = By.xpath("//input[@id='editcapage:textfielddefaultcrldistpoint']/following-sibling::input[1]");
        /**
         * CA Life Cycle / Renew Ca
         */
        static final By BUTTON_RENEW_CA = By.id("editcapage:buttonrenewca");

        static final By SELECT_CA = By.id("managecas:selectcas");
        /**
         * Crypto Token
         */
        static final By SELECT_CRYPTO_TOKEN = By.id("editcapage:selectcryptotoken");
        /**
         * CA Certificate Data / Signed By
         */
        static final By SELECT_SIGNED_BY = By.id("editcapage:cadatasignedby");
        /**
         * CA Certificate Data / Certificate Profile
         */
        static final By SELECT_CERT_PROFILE = By.id("editcapage:selectcertificateprofile");
        /**
         * defaultKey
         */
        static final By SELECT_DEFAULTKEY = By.id("editcapage:selectDefaultKey");
        /**
         * CA Life Cycle / Next CA key
         */
        static final By SELECT_CERTSIGNKEYRENEW = By.id("editcapage:selectcertsignkeyrenew");
        /**
         * Approval Settings / Next CA key
         */
        static final By SELECT_APPROVALPROFILES = By.xpath("//select[contains(@name, ':approvalProfile')]");

        /**
         * Select validator from Other Data list.
         *
         */
        static final By SELECT_VALIDATOR = By.name("editcapage:selectValidator");

        static final By INPUT_CANAME = By.id("managecas:textfieldcaname");
        /**
         * CA Certificate Data / Validity(*y *mo *d *h *m *s) or end date of the certificate
         */
        static final By INPUT_VALIDITY = By.id("editcapage:textfieldvalidity");
        /**
         * CA Certificate Data / Subject DN
         */
        static final By INPUT_SUBJECT_DN = By.id("editcapage:textfieldsubjectdn");
        /**
         * CRL Specific Data / CRL Expire Period
         */
        static final By INPUT_CRLPERIOD = By.id("editcapage:textfieldcrlperiod");
        /**
         * CRL Specific Data / CRL Issue Interval
         */
        static final By INPUT_CRLISSUEINTERVAL = By.id("editcapage:textfieldcrlissueinterval");
        /**
         * CRL Specific Data / CRL Overlap Time
         */
        static final By INPUT_CRLOVERLAPTIME = By.id("editcapage:textfieldcrloverlaptime");
        /**
         * Issue Distribution Point on CRL
         */
        static final By INPUT_CRLDISTRIBUTIONPOINT = By.id("editcapage:checkboxusecrldistributionpointoncrl");
        /**
         * Use CRL Partitions
         */
        static final By INPUT_USECRLPARTITIONS = By.id("editcapage:checkboxusecrlpartitions");
        /**
         * Number of Partitions
         */
        static final By INPUT_NUMBEROFPARTITIONS = By.id("editcapage:crlpartitions");
        /**
         * Number of Suspended Partitions
         */
        static final By INPUT_NUMBEROFSUPSENDEDPARTITIONS = By.id("editcapage:crlsuspendedpartitions");
        /**
         * Key sequence
         */
        static final By INPUT_KEYSEQUENCE = By.id("editcapage:keysequence");
        /**
         * CA Life Cycle / Use CA Name Change
         */
        static final By INPUT_CHECKBOXCANAMECHANGE = By.id("editcapage:idcheckboxcanamechange");
        /**
         * CA Life Cycle / New Subject DN
         */
        static final By INPUT_NEWSUBJECTDN = By.id("editcapage:idnewsubjectdn");

        /**
         * Directives / Enforce Unique Public Keys
         */
        static final By INPUT_CHECKBOXENFORCEUNIQUEPUBLICKEYS = By.id("editcapage:isdoenforceuniquepublickeys");

        /**
         * Directives / Enforce Unique DN
         */
        static final By INPUT_CHECKBOXENFORCEUNIQUEDN = By.id("editcapage:isdoenforceuniquedn");

        /**
         * certSignKey
         */
        static final By TEXT_CERTSIGNKEY = By.id("editcapage:certSignKey");

        /**
         * defaultKey
         */
        static final By TEXT_DEFAULTSIGNKEY = By.id("editcapage:defaultKey");

        /**
         * defaultKey
         */
        static final By TEXT_TESTSIGNKEY = By.id("editcapage:testKey");

        /**
         * crlSignKey
         */
        static final By TEXT_CRLSIGNKEY = By.id("editcapage:crlSignKey");

        static final By TEXT_DEFAULTCRLDISTRIBUTIONPOINT = By.id("editcapage:textfielddefaultcrldistpoint");

        // Dynamic references
        static By getCaListElementContainingText(final String text) {
            return By.xpath("//li[contains(text(), '" + text + "')]");
        }
    }

    /**
     * Enum of available CaType with corresponding locator
     */
    public enum CaType {

        X509(By.id("editcapage:catypex509")),
        CVC(By.id("editcapage:catypecvc"));

        private final By typeLocator;

        private CaType(By name) {
            this.typeLocator = name;
        }

        public By getLocatorId() {
            return this.typeLocator;
        }
    }

    public CaHelper(final WebDriver webDriver) {
        super(webDriver);
    }


    /**
     * Opens the page 'Certificate Authorities' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds a new CA. Browser will end up in the edit page for this CA once method is done.
     *
     * @param caName the name of the CA
     */
    public void addCa(final String caName) {
        fillInput(Page.INPUT_CANAME, caName);
        clickLink(Page.BUTTON_CREATE_CA);
    }

    /**
     * Selects CA from the list of CAs and clicks on 'Edit CA'
     *
     * @param caName the name of the CA to edit
     */
    public void edit(final String caName) {
        selectOptionByName(Page.SELECT_CA, caName + ", (Active)");
        clickLink(Page.BUTTON_EDIT);
    }
    
    public void edit(final String caName, final String status) {
        selectOptionByName(Page.SELECT_CA, caName + ", (" + status + ")");
        clickLink(Page.BUTTON_EDIT);
    }

    /**
     * Creates the CA
     */
    public void createCa() {
        clickLink(Page.BUTTON_CREATE);
    }

    /**
     * Saves the CA
     */
    public void saveCa() {
        clickLink(Page.BUTTON_SAVE);
    }
    
    public void saveAndInitializeCa() {
        clickLink(Page.BUTTON_SAVE_INITIALIZE);
    }

    /**
     * Selects the type of CA by clicking the specified CaType button.
     *
     * @param type of CA to set. CaType.X509 or CaType.CVC
     */
    public void setCaType(final CaType type) {
        clickLink(type.getLocatorId());
    }

    /**
     * Selects the specified certificate profile for the CA being edited.
     *
     * @param profileName of the certificate profile to select.
     */
    public void setCertificateProfile(final String profileName) {
        selectOptionByName(Page.SELECT_CERT_PROFILE, profileName);
    }

    /**
     * Select the validator from other data.
     *
     * @param validatorName
     */

    public void setOtherData(final String validatorName) {
        selectOptionByName(Page.SELECT_VALIDATOR, validatorName);
    }

    /**
     * Selects the specified Next CA key.
     *
     * @param nextCaKey Next CA key to select.
     */
    public void setNextCaKey(final String nextCaKey) {
        selectOptionByName(Page.SELECT_CERTSIGNKEYRENEW, nextCaKey);
    }

    /**
     * Selects Crypto Token from the drop down in the edit CA page
     *
     * @param tokenName of the token to select
     */
    public void setCryptoToken(final String tokenName) {
        selectOptionByName(Page.SELECT_CRYPTO_TOKEN, tokenName, Page.SELECT_DEFAULTKEY);
    }

    /**
     * Selects the specified CA from the "Signed By" drop down menu.
     *
     * @param caName of the CA to select
     */
    public void setSignedBy(final String caName) {
        selectOptionByName(Page.SELECT_SIGNED_BY, caName);
    }

    /**
     * Sets the CA's Subject DN.
     *
     * @param subjectDn the Subject DN to set
     */
    public void setSubjectDn(final String subjectDn) {
        fillInput(Page.INPUT_SUBJECT_DN, subjectDn);
    }

    /**
     * Sets the CA's validity.
     *
     * @param validityString (*y *mo *d *h *m *s) or end date of the certificate. E.g. '1y'
     */
    public void setValidity(final String validityString) {
        fillInput(Page.INPUT_VALIDITY, validityString);
    }

    /**
     * Sets the CA's CRL Expire Period.
     *
     * @param crlPeriodString CRL Expire Period(*y *mo *d *h *m)
     */
    public void setCrlPeriod(final String crlPeriodString) {
        fillInput(Page.INPUT_CRLPERIOD, crlPeriodString);
    }

    /**
     * Sets the CA's CRL Issue Interval.
     *
     * @param crlIssueInterval CRL Issue Interval(*y *mo *d *h *m)
     */
    public void setCrlIssueInterval(final String crlIssueInterval) {
        fillInput(Page.INPUT_CRLISSUEINTERVAL, crlIssueInterval);
    }

    /**
     * Sets the CA's CRL Overlap Time.
     *
     * @param crlOverlapTime CRL Overlap Time(*y *mo *d *h *m)
     */
    public void setCrlOverlapTime(final String crlOverlapTime) {
        fillInput(Page.INPUT_CRLOVERLAPTIME, crlOverlapTime);
    }

    /**
     * Check 'Use CA Name Change' checkbox  is  shown on page.
     */
    public void assertCheckboxcaNameChangePresent() {
        assertNotNull(findElement(Page.INPUT_CHECKBOXCANAMECHANGE));
    }

    /**
     * Asserts the element 'Use CA Name Change' is not shown on page.
     */
    public void assertCheckboxCaNameChangeNotPresent() {
        assertNull(findElementWithoutWait(Page.INPUT_CHECKBOXCANAMECHANGE));
    }

    /**
     * click 'Use CA Name Change'
     */
    public void checkUseCaNameChange() {
        clickLink(Page.INPUT_CHECKBOXCANAMECHANGE);
    }

    /**
     * Checks that a given CA exists in 'List of Certificate Authorities'.
     *
     * @param caName the name of the Certificate Profile
     */
    public void assertExists(final String caName) {
        final List<String> selectNames = getSelectNames(Page.SELECT_CA);
        assertNotNull(caName + " was not found in the List of Certificate Authorities", selectNames);
        assertTrue(caName + " was not found in the List of Certificate Authorities", selectNames.contains(caName + ", (Active)"));
    }

    /**
     * Calls the CA renew dialog
     *
     * @param expectedAlertMessage expected alert message.
     * @param isConfirmed          true to confirm, false otherwise.
     * @param expectedTitle        expected title message in of confirmed.
     * @param caName               CA name.
     */
    public void renewCaAndAssert(final String expectedAlertMessage, final boolean isConfirmed, final String expectedTitle, final String caName) {
        clickLink(Page.BUTTON_RENEW_CA);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
        if (isConfirmed) {
            assertTitleExists(expectedTitle);
        }
        assertExists(caName);
    }

    /**
     * Calls the CA delete dialog.
     *
     * @param expectedAlertMessage expected alert message.
     * @param isConfirmed          true to confirm, false otherwise.
     * @param expectedTitle        expected title message in of confirmed.
     * @param caName               CA name.
     */
    public void deleteCaAndAssert(final String expectedAlertMessage, final boolean isConfirmed, final boolean assertTitle, final String expectedTitle, final String caName) {
        selectOptionByName(Page.SELECT_CA, caName + ", (Active)");
        clickLink(Page.BUTTON_DELETE_CA);
        assertAndConfirmAlertPopUp(expectedAlertMessage, isConfirmed);
        if (assertTitle) {
            assertTitleExists(expectedTitle);
        }
    }

    private void assertTitleExists(final String titleText) {
        final WebElement titleWebElement = findElement(Page.getCaListElementContainingText(titleText));
        if (titleWebElement == null) {
            fail("Title was not found [" + titleText + "].");
        }
    }

    /**
     * Selects the Approval Profile by name for all 'Add/Edit End Entity', 'Key Recovery', 'Revocation' and 'CA Service Activation'.
     *
     * @param approvalProfileName approval profile name.
     */
    public void selectAllApprovalProfileNames(final String approvalProfileName) {
        final List<WebElement> approvalDropDowns = findElements(Page.SELECT_APPROVALPROFILES);
        for (WebElement approvalDropDown : approvalDropDowns) {
            selectOptionByName(approvalDropDown, approvalProfileName);
        }
    }

    /**
     * Asserts the element 'certSignKey' value is correct.
     *
     * @param value expected value.
     */
    public void assertCertSignKeyValue(final String value) {
        assertEquals(
                "Unexpected value for certSignKey",
                value,
                getElementText(Page.TEXT_CERTSIGNKEY)
        );
    }


    /**
     * Asserts the element 'defaultKey' value is correct.
     *
     * @param value expected value.
     */
    public void assertDefaultKeyValue(final String value) {
        assertEquals(
                "Unexpected value for DefaultKey",
                value,
                getElementText(Page.TEXT_DEFAULTSIGNKEY)
        );
    }


    /**
     * Asserts the element 'testKey' value is correct.
     *
     * @param value expected value.
     */
    public void assertTestKeyValue(final String value) {
        assertEquals(
                "Unexpected value for TestKey",
                value,
                getElementText(Page.TEXT_TESTSIGNKEY)
        );
    }

    /**
     * Asserts the element 'crlSignKey' value is correct.
     *
     * @param value expected value.
     */
    public void assertCrlSignKeyValue(final String value) {
        assertEquals(
                "Unexpected value for crlSignKey",
                value,
                getElementText(Page.TEXT_CRLSIGNKEY)
        );
    }

    /**
     * Asserts the element 'Key sequence' value is correct.
     *
     * @param value expected value.
     */
    public void assertKeysequence(final String value) {
        assertEquals(
                "Unexpected value for Key sequence",
                value,
                getElementValue(Page.INPUT_KEYSEQUENCE)
        );
    }

    /**
     * Asserts the element 'Next CA key' value is correct.
     *
     * @param value expected value.
     */
    public void assertSelectCertsignKeyRenew(final String value) {
        assertEquals(
                "Unexpected value for Next CA key",
                value,
                getFirstSelectedOption(Page.SELECT_CERTSIGNKEYRENEW)
        );
    }

    /**
     * Asserts the element 'New Subject DN' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertNewSubjectDnIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'New Subject DN' isEnabled [" + isEnabled + "] by default",
                isEnabled,
                isEnabledElement(Page.INPUT_NEWSUBJECTDN)
        );
    }

    /**
     * Asserts the element 'New Subject DN' is not shown on page
     */
    public void assertNewSubjectDnNotPresent() {
        assertNull(findElementWithoutWait(Page.INPUT_NEWSUBJECTDN));
    }

    /**
     * Check or uncheck Enforce Unique Public Keys
     *
     * @param check
     */
    public void checkEnforceUniquePublicKeys(Boolean check) {
        toggleCheckbox(Page.INPUT_CHECKBOXENFORCEUNIQUEPUBLICKEYS, check);
    }

    public void checkEnforceUniqueDN(Boolean check) {
        toggleCheckbox(Page.INPUT_CHECKBOXENFORCEUNIQUEDN, check);
    }

    /**
     * Check the Issuing Distribution Point on Crls
     *
     * @param check
     */
    public void checkIssuingDistPointOnCrls(Boolean check) {
        toggleCheckbox(Page.INPUT_CRLDISTRIBUTIONPOINT, check);
    }

    /**
     * Check the Use Crl Partitions checkbox
     *
     * @param check
     */
    public void checkUseCrlPartitions(Boolean check) {
        toggleCheckbox(Page.INPUT_USECRLPARTITIONS, check);
    }

    /**
     * Sets the number of crl partitions
     *
     * @param iPartitions
     */
    public void setNumberOfPartitions(String iPartitions) {
            fillInput(Page.INPUT_NUMBEROFPARTITIONS, iPartitions);
    }

    /**
     * Sets default crl Distribution Point
     *
     * @param crlDistributionPoint
     */
    public void setDefaultCrlDistributionPoint(String crlDistributionPoint) {
            fillInput(Page.TEXT_DEFAULTCRLDISTRIBUTIONPOINT, crlDistributionPoint);
    }

    /**
     * Sets the number of suspended crl partitions
     *
     * @param iSuspended
     */
    public void setNumberOfSuspendedPartitions(String iSuspended) {
        fillInput(Page.INPUT_NUMBEROFSUPSENDEDPARTITIONS, iSuspended);
    }

    /**
     * Click the generate for Default CRL Distribution Point
     *
     */
    public void clickGenerateDefaultCrlDistributionPoint() {
        clickLink(Page.BUTTON_GENERATEDEFAULTCRLDISTRIBUTIONPOINT);
    }

    /**
     * Asserts a url was generated
     *
     * @param sValue
     */
    public void assertDefaultCrlDistributionPointUri(String sValue) {
        assertEquals(sValue, getElementValue(Page.TEXT_DEFAULTCRLDISTRIBUTIONPOINT));
    }

    public void assertHasErrorMessage(final String errorMessageText) {
        assertErrorMessageAppears(errorMessageText, "CA save error message was not found", "Expected CA error message was not displayed");
    }
}
