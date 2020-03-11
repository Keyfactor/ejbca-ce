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
 * Helper class for EJBCA Web Tests using CA Activation functions.
 * @version $Id$
 */

public class CaActivationHelper extends BaseHelper {
    
    public static class Page {
        static final String CA_ACTIVATION_PAGE_URI = "/ejbca/adminweb/ca/caactivation.xhtml";
        static final String CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_CODE = "foo123";
        
        static final By CA_ACTIVATION_PAGE_LINK = By.id("caCaactivation");
        static final By CA_ACTIVATION_APPLY_BUTTON = By.id("caActivation:applyButton");
        static final By CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_INPUT_TEXTFIELD = By.id("caActivation:authCode");
        static final By CA_ACTIVATION_CRYPTOTOKEN_EDIT_BUTTON = By.xpath("//tr/td/input[contains(@value, 'Switch to edit mode')]");
        static final By CA_ACTIVATION_CRYPTOTOKEN_AUTO_ACTIVATION_CHECKBOX = By.id("currentCryptoTokenForm:currentCryptoTokenAutoActivate");
        static final By CA_ACTIVATION_CRYPTOTOKEN_SAVE_BUTTON = By.xpath("//tr/td/span/input[contains(@value, 'Save')]");
        
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
    
    public CaActivationHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.CA_ACTIVATION_PAGE_LINK, Page.CA_ACTIVATION_PAGE_URI);
    }
    
    public void setCaServiceStateOffline(String cryptotoken) {
        toggleCheckbox(Page.getCaServiceActionCheckboxByCryptoTokenName(cryptotoken), false);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }

    public void setCaServiceStateActive(String cryptotoken) {
        toggleCheckbox(Page.getCaServiceActionCheckboxByCryptoTokenName(cryptotoken), true);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
    
    public void openPageCaCryptoTokenEditPage(String cryptotoken) {
        clickLink(Page.getCaCryptoTokenLink(cryptotoken));
        clickLink(Page.CA_ACTIVATION_CRYPTOTOKEN_EDIT_BUTTON);
    }
    
    public void editCryptoTokenSetNoAutoActivation() {
        toggleCheckbox(Page.CA_ACTIVATION_CRYPTOTOKEN_AUTO_ACTIVATION_CHECKBOX, false);
        clickLink(Page.CA_ACTIVATION_CRYPTOTOKEN_SAVE_BUTTON);
    }
    
    public void setCaCryptoTokenStateOffline(String cryptotoken) {
        toggleCheckbox(Page.getCaCryptoTokenCheckboxByCryptoTokenName(cryptotoken), false);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
    
    public void setCaCryptoTokenStateActive(String cryptotoken) {
        toggleCheckbox(Page.getCaCryptoTokenCheckboxByCryptoTokenName(cryptotoken), true);
        fillInput(Page.CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_INPUT_TEXTFIELD, Page.CA_ACTIVATION_CRYPTOTOKEN_ACTIVATION_CODE);
        clickLink(Page.CA_ACTIVATION_APPLY_BUTTON);
    }
}


