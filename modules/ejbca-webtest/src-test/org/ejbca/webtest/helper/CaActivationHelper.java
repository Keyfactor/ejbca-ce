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

/**
 * Helper class for EJBCA Web Tests using the CA Activation functions.
 * @version $Id$
 */

public class CaActivationHelper extends BaseHelper {
    
    /**
     * Contains constants and references of the 'CA Activation' page.
     */
    public static class Page {
        // General
        static final String CA_ACTIVATION_PAGE_URI = "/ejbca/adminweb/ca/caactivation.xhtml";
        static final By CA_ACTIVATION_PAGE_LINK = By.id("caCaactivation");
        // Ca Crypto Token Activation code
        static final String CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_CODE_FOO123 = "foo123";
               
        static final By CA_ACTIVATION_APPLY_BUTTON = By.id("caActivation:applyButton");
        static final By CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_INPUT_TEXTFIELD = By.id("caActivation:authCode");
        static final By CA_ACTIVATION_CRYPTOTOKEN_AUTO_ACTIVATION_CHECKBOX = By.id("currentCryptoTokenForm:currentCryptoTokenAutoActivate");
        static final By CA_ACTIVATION_CRYPTOTOKEN_EDIT_BUTTON = By.xpath("//tr/td/input[contains(@value, 'Switch to edit mode')]");
        static final By CA_ACTIVATION_CRYPTOTOKEN_SAVE_BUTTON = By.xpath("//tr/td/span/input[contains(@value, 'Save')]");
        
        // Dynamic references
        static By getCaServiceActionCheckboxByCryptoTokenName(final String cryptotoken) {
            return By.xpath("//tr/td[contains(node(), '" + cryptotoken + "')]/following::input[2]");
        }
        
        static By getCaCryptoTokenCheckboxByCryptoTokenName(final String cryptotoken) {
            return By.xpath("//tr/td[contains(node(), '" + cryptotoken + "')]/following::input[1]");
        }
        
        static By getCaCryptoTokenLink(final String cryptotoken) {
            return By.xpath("//tr/td/a[contains(node(), '" + cryptotoken + "')]");
        }
    }
    
    /**
     * Constructor
     * @param webDriver the webdriver
     */
    public CaActivationHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    /**
     * Open CA Activation page
     * @param webUrl CA Activation page URL
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.CA_ACTIVATION_PAGE_LINK, Page.CA_ACTIVATION_PAGE_URI);
    }
    
    /**
     * Set Ca Service off-line for CA with cryptotoken
     * @param cryptotoken CA cryptotoken
     */
    public void setCaServiceStateOffline(String cryptotoken) {
        toggleCheckbox(Page.getCaServiceActionCheckboxByCryptoTokenName(cryptotoken), false);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
    
    /**
     * Set Ca Service active for CA with cryptotoken
     * @param cryptotoken CA cryptotoken
     */
    public void setCaServiceStateActive(String cryptotoken) {
        toggleCheckbox(Page.getCaServiceActionCheckboxByCryptoTokenName(cryptotoken), true);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
    
    /**
     * Open CryptoToken edit page from CA Activation page for this cryptotoken 
     * @param cryptotoken CA cryptotoken
     */
    public void openPageCaCryptoTokenEditPage(String cryptotoken) {
        clickLink(Page.getCaCryptoTokenLink(cryptotoken));
        clickLink(Page.CA_ACTIVATION_CRYPTOTOKEN_EDIT_BUTTON);
    }
    
    /**
     * Uncheck the auto-activation checkbox for this cryptotoken
     */
    public void editCryptoTokenSetNoAutoActivation() {
        toggleCheckbox(Page.CA_ACTIVATION_CRYPTOTOKEN_AUTO_ACTIVATION_CHECKBOX, false);
        clickLink(Page.CA_ACTIVATION_CRYPTOTOKEN_SAVE_BUTTON);
    }
    
    /**
     * Set Ca Cryptotoken state off-line for CA with cryptotoken
     * @param cryptotoken CA cryptotoken
     */
    public void setCaCryptoTokenStateOffline(String cryptotoken) {
        toggleCheckbox(Page.getCaCryptoTokenCheckboxByCryptoTokenName(cryptotoken), false);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
    
    /**
     * Set Ca Cryptotoken state active for CA with cryptotoken
     * @param cryptotoken CA cryptotoken
     */
    public void setCaCryptoTokenStateActive(String cryptotoken) {
        toggleCheckbox(Page.getCaCryptoTokenCheckboxByCryptoTokenName(cryptotoken), true);
        fillInput(Page.CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_INPUT_TEXTFIELD, Page.CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_CODE_FOO123);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
}


