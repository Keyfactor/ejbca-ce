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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.junit.rules.TemporaryFolder;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import static org.junit.Assert.assertEquals;

/**
 * Helper class for UI tests related to Trusted OAuth Provider configuration
 *
 */
public class OauthProvidersHelper extends BaseHelper {
    public OauthProvidersHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    public static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFJY5TplekPjaNgCckezeyhkccA8O\n" +
            "63Sj84rZ1RCRoJ7vHa8FF2IIbF/S1iEb/gbkmqNJ4K3m+oNzcr76yoH3Dg==\n" +
            "-----END PUBLIC KEY-----";

    public static class Page {
        static final By SYSCONFIG_BUTTON_ADD = By.id("oauthkeysform:addOauthKey");
        static final By PROVIDER_TYPE_SELECT_OPTION = By.id("editOAuthKeyForm:selectOneMenuProviderType");
        static final By PROVIDER_NAME_INPUT_FIELD = By.id("editOAuthKeyForm:label");
        static final By PUBLIC_KEY_METHOD_FIELD = By.id("editOAuthKeyForm:selectOneMenuUploadWay");
        static final By PUBLIC_KEY_INPUT_FIELD = By.id("editOAuthKeyForm:editedOAuthKeyFile");
        static final By KEYID_INPUT_FIELD = By.id("editOAuthKeyForm:keyId");
        static final By PUBLIC_KEY_FINGERPRINT_FIELD = By.id("editOAuthKeyForm:publicKeyFingerprint");
        static final By TABLE_ROW_DATA = By.xpath("//table[@class='grid oauthkeyTable']/tbody/tr/td[1]/span");
        static final By URL_INPUT_FIELD = By.id("editOAuthKeyForm:keyUrl");
        static final By SKEWLIMIT_INPUT_FIELD = By.id("editOAuthKeyForm:editedProviderSkewLimit");
        static final By REALM_INPUT_FIELD = By.id("editOAuthKeyForm:realm");
        static final By TENANT_INPUT_FIELD = By.id("editOAuthKeyForm:realm");
        static final By AUDIENCE_INPUT_FIELD = By.id("editOAuthKeyForm:audience");
        static final By SCOPE_INPUT_FIELD = By.id("editOAuthKeyForm:scope");
        static final By CLIENT_INPUT_FIELD = By.id("editOAuthKeyForm:client");
        static final By CLIENT_SECRET_INPUT_FIELD = By.id("editOAuthKeyForm:clientSecret");
        static final By BUTTON_SAVE = By.id("editOAuthKeyForm:saveOAuthKeyEdit");
        static final By BUTTON_ADD = By.id("editOAuthKeyForm:addOauthKey");
        static final By BUTTON_UPLOAD = By.id("editOAuthKeyForm:addPublicKey");
        static final By BUTTON_BACK = By.id("editOAuthKeyForm:goBack");

        static By getTextFromTable(final String text) {
            return By.xpath("//tr/td/span[contains(text(), '" + text + "')]");
        }
        
        static By getViewOauthProviderButton(final String keyid) {
            return By.xpath("//table/tbody/tr/td[span[contains(text(), '" + keyid + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'viewOauthKeyButton')]");
        }
        
        static By getEditOauthProviderButton(final String keyid) {
            return By.xpath("//table/tbody/tr/td[span[contains(text(), '" + keyid + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'editOauthKeyButton')]");
        }
        
        static By getRemoveOauthProviderButton(final String keyid) {
            return By.xpath("//table/tbody/tr/td[span[contains(text(), '" + keyid + "')]]/" +
                    "following-sibling::td/input[contains(@id, 'removeOauthKeyButton')]");
        }
    }
    
    public void startAddingProvider() {
        clickLink(Page.SYSCONFIG_BUTTON_ADD);
    }
    
    public void fillProviderNameField(final String inputText) {
        fillInput(Page.PROVIDER_NAME_INPUT_FIELD, inputText);
    }

    public void fillKeyIdField(final String inputText) {
        fillInput(Page.KEYID_INPUT_FIELD, inputText);
    }
    
    public void fillUrlField(final String inputText) {
        fillInput(Page.URL_INPUT_FIELD, inputText);
    }

    public void fillPublicKeyFileField(final File inputFile) {
        fillInput(Page.PUBLIC_KEY_INPUT_FIELD, inputFile.toString());
    }

    public void fillSkewLimitField(final String inputNumber) {
        fillInput(Page.SKEWLIMIT_INPUT_FIELD, inputNumber);
    }
    
    public void fillTenantField(final String inputText) {
        fillInput(Page.TENANT_INPUT_FIELD, inputText);
    }

    public void fillAudienceField(final String inputText) {
        fillInput(Page.AUDIENCE_INPUT_FIELD, inputText);
    }
    
    public void fillRealmField(final String inputText) {
        fillInput(Page.REALM_INPUT_FIELD, inputText);
    }
    
    public void fillScopeField(final String inputText) {
        fillInput(Page.SCOPE_INPUT_FIELD, inputText);
    }
    
    public void fillClientField(final String inputText) {
        fillInput(Page.CLIENT_INPUT_FIELD, inputText);
    }
    
    public void fillSecretField(final String inputText) {
        fillInput(Page.TENANT_INPUT_FIELD, inputText);
    }
    
    public void fillClientSecretField(final String inputText) {
        fillInput(Page.CLIENT_SECRET_INPUT_FIELD, inputText);
    }
    
    public void selectProviderType(final OAuthProviderType type) {
        if (type != null) {
            selectOptionByName(Page.PROVIDER_TYPE_SELECT_OPTION, type.getLabel());
        }
    }

    public void assertElementExistsInTable(final String matchTextWith) {
        assertElementExists(Page.getTextFromTable(matchTextWith), "Element with text:" + matchTextWith + " does not exist in the table.");
    }
    
    public void assertElementDoesNotExistInTable(final String matchTextWith) {
        assertElementDoesNotExist(Page.getTextFromTable(matchTextWith), "Element with text:" + matchTextWith + " exists in the table.");
    }

    public void assertIsTableRowsCorrectOrder(int rowNum, String rowData) {
        final List<WebElement> tableRows = findElements(Page.TABLE_ROW_DATA);
        assertEquals(rowData, tableRows.get(rowNum).getText());
    }
    
    public void assertProviderNameText(String text) {
        assertEquals(
                "'OAuth Provider Name' field text [" + text + "]",
                text,
                getElementValue(Page.PROVIDER_NAME_INPUT_FIELD)
        );
    }
    
    public void assertKeyIdentifierText(String text) {
        assertEquals(
                "'OAuth Key Identifier' field text [" + text + "]",
                text,
                getElementValue(Page.KEYID_INPUT_FIELD)
        );
    }
    
    public void assertCurrentPublicKeyFingerprintText(String text) {
        assertEquals(
                "'Current Public Key' field text [" + text + "]",
                text,
                getElementText(Page.PUBLIC_KEY_FINGERPRINT_FIELD)
        );
    }
    
    public void assertSkewLimitText(String text) {
        assertEquals(
                "'Skew Limit' field text [" + text + "]",
                text,
                getElementValue(Page.SKEWLIMIT_INPUT_FIELD)
        );
    }
    
    public void pressViewOauthProviderButton(final String label) {
        clickLink(Page.getViewOauthProviderButton(label));
    }
    
    public void pressEditOauthProviderButton(final String label) {
        clickLink(Page.getEditOauthProviderButton(label));
    }
    
    public void pressRemoveOauthProviderButton(final String label) {
        clickLink(Page.getRemoveOauthProviderButton(label));
        assertAndConfirmAlertPopUp("Are you sure you want to remove this OAuth trusted provider: " + label + "?", true);
    }
    
    public void pressSaveOauthProviderButton() {
        clickLink(Page.BUTTON_SAVE);
    }
    
    public void pressAddOauthProviderButton() {
        clickLink(Page.BUTTON_ADD);
    }
    
    public void pressUploadButton() {
        clickLink(Page.BUTTON_UPLOAD);
    }
    
    public void pressBackButton() {
        clickLink(Page.BUTTON_BACK);
    }
    
    public File createPublicKeyFile(final TemporaryFolder folder, final String fileContent) throws IOException {
        File publicKeyFile = folder.newFile("public1.pem");
        FileWriter fileWriter = new FileWriter(publicKeyFile);
        BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
        try {
            bufferedWriter.write(fileContent);
        } finally {
            bufferedWriter.close();
            fileWriter.close();
        }
        return publicKeyFile;
    }
}
