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

import static org.junit.Assert.assertEquals;

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * ACME helper class for EJBCA Web Tests.
 *
 *  @version $Id$
 */
public class AcmeHelper extends BaseHelper {

    /**
     * Contains references of the 'ACME Configuration' page.
     * 
     */
    public static class Page {
        //General
        static final String PAGE_URI = "/ejbca/adminweb/sysconfig/acmeconfiguration.xhtml";
        static final By PAGE_LINK = By.id("sysConfigAcme");
        static final By NOUNCE_TEXTFIELD = By.xpath("//input[@title='Integer number']");
        static final By ADD_ALIAS_ERROR = By.xpath("//li[@class='errorMessage']");
        static final By DEFAULT_ACME_CONFIG_LIST = By.id("acmeConfigs:selectOneMenuEEP");
        static final String DELETE_ALIAS_CONFIRM_MESSAGE = "Are you sure you want to delete this?";

        //Edit Alias fields
        static final By SELECT_ONE_EEP = By.id("currentAliasForm:selectOneMenuEEP");
        static final By PRE_AUTH_ALLOWED = By.id("currentAliasForm:preautorisation");
        static final By WILDCARD_ALLOWED = By.id("currentAliasForm:wildcard");
        static final By SITE_URL = By.id("currentAliasForm:webUrl");
        static final By TERMS_URL = By.id("currentAliasForm:termsUrl");
        static final By TERMS_INPUT_URL = By.id("currentAliasForm:termsOfServiceUrl");
        static final By VERSION_APPROVAL = By.id("currentAliasForm:versionApproval");
        static final By DNS_RESOLVER = By.id("currentAliasForm:dnsResolver");
        static final By DNS_PORT = By.id("currentAliasForm:dnsPort");
        static final By USE_DNSSEC = By.id("currentAliasForm:useDnsSec");
        static final By DNSSEC_TRUST_ANCHOR = By.id("currentAliasForm:dnssecTrustAnchor");

        //Buttons
        static final By BUTTON_ADD_ALIAS = By.xpath("//a[@title='Add Alias']");
        static final By BUTTON_SAVE = By.id("acmeConfigs:save");
        static final By BUTTON_RENAME_ALIAS = By.xpath("//a[@title='Rename Alias']");
        static final By BUTTON_DELETE_ALIAS = By.xpath("//a[@title='Delete Alias']");
        static final By BUTTON_EDIT_ALIAS_FIELDS = By.xpath("//input[@value='Switch to edit mode']");

        //Dynamic Reference

        //  name - name of the Alias
        //  buttonName - Rename / Delete
        static By getActionsButton(String name, String buttonName) {
            return By.xpath("//a[@href='acmealiasconfiguration.xhtml?alias=" + name + "']/following::td/a[@title='" + buttonName + " Alias']");
        }

        static By getAliasEditButton(String name) {
            return By.xpath("//a[@href='acmealiasconfiguration.xhtml?alias=" + name + "']");
        }
    }

    public AcmeHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the 'Admin Web' page and asserts the correctness of URI path.
     *
     * @param webUrl the URL of the AdminWeb.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }

    /**
     * Adds text to alert window and accepts.
     *
     * @param text The adding text.
     */
    public void alertTextfieldAndAccept(String text) {
        alertWindow().sendKeys(text);
        alertWindow().accept();
    };

    /**
     * Switches to the alert window. 
     *
     */
    public Alert alertWindow() {
        Alert alert = webDriver.switchTo().alert();
        return alert;
    }

    /**
     * Clicks on the Alias name
     *
     */
    public void clickAlias(String name) {
        clickLink(Page.getAliasEditButton(name));
    }
    
    /**
     * Clicks the 'Add' button
     *
     */
    public void clickAdd() {
        clickLink(Page.BUTTON_ADD_ALIAS);
    }

    /**
     * Clicks the 'Rename' button for the correct Alias. 
     *
     * @param name The name of the Alias.
     */
    public void rename(String name) {
        clickLink(Page.getActionsButton(name, "Rename"));
    }
    
    /**
     * Clicks the 'Switch to edit mode' button
     *
     */
    public void clickEdit() {
        clickLink(Page.BUTTON_EDIT_ALIAS_FIELDS);
    }

    /**
     * Clicks the 'Delete' button for the correct Alias. 
     *
     * @param name The name of the Alias.
     */
    public void deleteWithName(String name) {
        clickLink(Page.getActionsButton(name, "Delete"));
        assertAndConfirmAlertPopUp("Are you sure you want to delete this?", true);
    }

    /**
     * Checks that ACME alias already exists when trying to add a new alias. 
     *
     *@param name The alias name to check.
     */
    public void confirmNewAliasAlreadyExists(String name) {
        assertErrorMessageAppears("Cannot add alias. Alias '" + name + "' already exists."
                ,"Cannot Add Alias error message was not found"
                ,"Expected Alias error message was not displayed");
    }

    /**
     * Checks that ACME alias already exists when renaming an alias. 
     *
     *@param name The alias name to check.
     */
    public void confirmRenamedAliasAlreadyExists(String name) {
        assertErrorMessageAppears("Cannot rename alias. Either the new alias is empty or it already exists."
                ,"Cannot Rename Alias error message was not found"
                ,"Expected Alias error message was not displayed");
    }

    /**
     * Asserts the element 'End Entity Profile' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertEEPIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'End Entity Profile' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SELECT_ONE_EEP)
        );
    }

    /**
     * Asserts the element 'Pre-Authorization Allowed' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertPreAuthorizationAllowedIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Pre-Authorization Allowed' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.PRE_AUTH_ALLOWED)
        );
    }

    /**
     * Asserts the element 'Pre-Authorization Allowed' is/isn't selected.
     *
     * @param isSelected true for selected and false for not selected.
     */
    public void assertPreAuthorizationAllowedIsSelected(final boolean isSelected) {
        assertEquals(
                "'Pre-Authorization Allowed' field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.PRE_AUTH_ALLOWED)
        );
    }

    
    /**
     * Asserts the element 'Wildcard Certificate Issuance Allowed' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertWildcardIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Wildcard Certificate Issuance Allowed' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.WILDCARD_ALLOWED)
        );
    }
    
    /**
     * Asserts the element 'Wildcard Certificate Issuance Allowed' is/isn't selected.
     *
     * @param isSelected true for enabled and false for not selected.
     */
    public void assertWildcardIsSelected(final boolean isSelected) {
        assertEquals(
                "'Wildcard Certificate Issuance Allowed' field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.WILDCARD_ALLOWED)
        );
    }

    /**
     * Asserts the element 'Site URL' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertSiteURLIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Site URL' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.SITE_URL)
        );
    }

    /**
     * Asserts the element 'Site URL' has the correct text.
     *
     * @param text the expected text of the element.
     */
    public void assertSiteURLText(String text) {
        assertEquals(
                "'Site URL' field text [" + text + "]",
                text,
                getElementText(Page.SITE_URL)
        );
    }

    /**
     * Asserts the element 'Terms of Service URL' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertTermsURLIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Terms of Service URL' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.TERMS_INPUT_URL)
        );
    }
    
    /**
     * Asserts the element 'Terms of Service URL' has the correct text.
     *
     * @param text the expected text of the element.
     */
    public void assertTermsURLText(String text) {
        assertEquals(
                "'Terms of Service URL' field text [" + text + "]",
                text,
                getElementText(Page.TERMS_URL)
        );
    }

    /**
     * Asserts the element 'Require client approval for Terms of Service changes' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertVersionApprovalIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Require client approval for Terms of Service changes' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.VERSION_APPROVAL)
        );
    }
    
    /**
     * Asserts the element 'Require client approval for Terms of Service changes' is/isn't selected.
     *
     * @param isSelected true for selected and false for not selected.
     */
    public void assertVersionApprovalIsSelected(final boolean isSelected) {
        assertEquals(
                "'Require client approval for Terms of Service changes' field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.VERSION_APPROVAL)
        );
    }

    /**
     * Asserts the element 'DNS Resolver' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDNSResolverIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'DNS Resolver' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.DNS_RESOLVER)
        );
    }
    
    /**
     * Asserts the element 'DNS Resolver' has the correct text.
     *
     * @param text the expected text of the element.
     */
    public void assertDNSResolverText(String text) {
        assertEquals(
                "'DNS Resolver' field text [" + text + "]",
                text,
                getElementText(Page.DNS_RESOLVER)
        );
    }

    /**
     * Asserts the element 'DNS Port' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDNSPortIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'DNS Port' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.DNS_PORT)
        );
    }
    
    /**
     * Asserts the element 'DNS Port' has the correct text.
     *
     * @param text the expected text of the element.
     */
    public void assertDNSPortText(String text) {
        assertEquals(
                "'DNS Port' field text [" + text + "]",
                text,
                getElementText(Page.DNS_PORT)
        );
    }

    /**
     * Asserts the element 'Validate DNSSEC' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertValidateDNSSECIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'Validate DNSSEC' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.USE_DNSSEC)
        );
    }
    
    /**
     * Asserts the element 'Validate DNSSEC' is/isn't selected.
     *
     * @param isSelected true for selected and false not selected.
     */
    public void assertValidateDNSSECIsSelected(final boolean isSelected) {
        assertEquals(
                "'Validate DNSSEC' field isSelected [" + isSelected + "]",
                isSelected,
                isSelectedElement(Page.USE_DNSSEC)
        );
    }

    /**
     * Asserts the element 'DNSSEC Trust Anchor' is enabled/disabled.
     *
     * @param isEnabled true for enabled and false for disabled.
     */
    public void assertDNSSECTrustAnchorIsEnabled(final boolean isEnabled) {
        assertEquals(
                "'DNSSEC Trust Anchor' field isEnabled [" + isEnabled + "]",
                isEnabled,
                isEnabledElement(Page.DNSSEC_TRUST_ANCHOR)
        );
    }
    
    /**
     * Asserts the element 'DNSSEC Trust Anchor' has the correct text.
     *
     * @param text the expected text of the element.
     */
    public void assertDNSSECTrustAnchorText(String text) {
        assertEquals(
                "'DNSSEC Trust Anchor' field text [" + text + "]",
                text,
                getElementText(Page.DNSSEC_TRUST_ANCHOR)
        );
    }
}