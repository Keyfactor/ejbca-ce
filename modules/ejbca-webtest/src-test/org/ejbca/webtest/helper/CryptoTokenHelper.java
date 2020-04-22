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


import static org.junit.Assert.fail;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * 
 * Crypto Token helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 *
 */
public class CryptoTokenHelper extends BaseHelper {

    /**
     * Contains constants and references of the 'Crypto Tokens' page.
     */
    public static class Page {
        // General
        static final String NEW_TOKEN_LINK_TEXT = "Create new...";
        static final String PAGE_URI = "/ejbca/adminweb/cryptotoken/cryptotokens.xhtml";
        static final String TOKEN_TYPE_SOFT = "SOFT";
      
        static final By AUTO_ACTIVATION_CHECKBOX = By.id("currentCryptoTokenForm:currentCryptoTokenAutoActivate");
        static final By BUTTON_GENERATE = By.xpath("//tr/td/input[contains(@value, 'Generate new key pair')]");
        static final By BUTTON_SAVE = By.xpath("//tr/td/span/input[contains(@value, 'Save')]");
        static final By CREATE_NEW_TOKEN_LINK = By.xpath("//a[text()='" + NEW_TOKEN_LINK_TEXT + "']");
        static final By CRYPTOTOKEN_AUTH_CODE_REPEAT_TEXTFIELD = By.id("currentCryptoTokenForm:currentCryptoTokenSecret2");
        static final By CRYPTOTOKEN_AUTH_CODE_TEXTFIELD = By.id("currentCryptoTokenForm:currentCryptoTokenSecret1");
        static final By CRYPTOTOKEN_KEY_ALIAS_TEXTFIELD = By.xpath("//tr/td/input[contains(@title, 'Alias, string')]");
        static final By CRYPTOTOKEN_NAME_INPUT_TEXTFIELD = By.id("currentCryptoTokenForm:currentCryptoTokenNameText");
        static final By PAGE_LINK = By.id("caCryptotokens");
        static final By SELECT_CRYPTOTOKEN_KEYSPEC = By.xpath("//tr/td/select[1]");
        static final By SELECT_TOKEN_TYPE = By.id("currentCryptoTokenForm:selectOneMenuType");
                
        // Dynamic references
        static By getTokenOptionContainingText(final String text) {
            return By.xpath("//td/a/span[text()='" + text + "']");
        }
        
        // name - name of the alias
        // buttonName - Test / Remove
        static By getTokenAliasButton(String name, String text) {
           return By.xpath("//form[@id='currentCryptoTokenAliasesForm']//td[contains(text(),'"+name+"')]/following-sibling::td/input[@value='"+text+"']");
        }
    }
    
    public CryptoTokenHelper(WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Opens the page 'CryptoTokens' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    /**
     * Opens the page to create a new CryptoToken.
     * 
     */
    public void openPageNewCryptoToken() {
        clickLink(Page.CREATE_NEW_TOKEN_LINK);
    }
    
    /**
     * Sets a name for the new CryptoToken.
     * 
     * @param cryptoTokenName is the CryptoToken name.
     */
    public void setNewCryptoTokenName(String cryptoTokenName) {
        fillInput(Page.CRYPTOTOKEN_NAME_INPUT_TEXTFIELD, cryptoTokenName);
    }
    
    /**
     * Sets the CryptoToken type for this CryptoToken (e.g. PKCS#11, SOFT, CP5).
     * 
     * @param type is the CryptoToken type.
     */
    public void setCryptoTokenType(final String type) {
        selectOptionByName(Page.SELECT_TOKEN_TYPE, Page.TOKEN_TYPE_SOFT);
    }
    
    /**
     * Sets the authentication code for this CryptoToken.
     * 
     * @param code is the authentication code.
     */
    public void setTokenAuthCode(final String code) {
        fillInput(Page.CRYPTOTOKEN_AUTH_CODE_TEXTFIELD, code);
        fillInput(Page.CRYPTOTOKEN_AUTH_CODE_REPEAT_TEXTFIELD, code);
    }
    
    /**
     * Sets auto activation true or false for this CryptoToken. 
     * 
     * @param use is the boolean for how to configure auto activation, true or false.
     */
    public void setAutoActivation(final boolean use) {
        toggleCheckbox(Page.AUTO_ACTIVATION_CHECKBOX, use);
    }
    
    /**
     * Saves a new CryptoToken.
     */
    public void saveToken() {
        clickLink(Page.BUTTON_SAVE);
    }
    
    /**
     * Opens the CryptoToken page for the given CryptoToken
     * 
     * @param tokenName is the name of the CryptoToken
     */
    public void openCryptoTokenPageByName(String tokenName) {
        clickLink(Page.getTokenOptionContainingText(tokenName));
    }
    
    /**
     * Generates a new key pair on the CryptoToken
     * 
     * @param keyAlias is the alias for the generated key
     * @param keySpec is the key specification for the key pair
     */
    public void generateKey(String keyAlias, String keySpec) {
        fillInput(Page.CRYPTOTOKEN_KEY_ALIAS_TEXTFIELD, keyAlias);
        selectOptionByName(Page.SELECT_CRYPTOTOKEN_KEYSPEC, keySpec);
        clickLink(Page.BUTTON_GENERATE);
    }
    
    /**
     * Checks that a given CryptoToken does not exist in the table of available tokens.
     * 
     * @param cryptoTokenName the name of the CryptoToken to check for.
     */
    public void assertTokenDoesNotExist(String cryptoTokenName) {
        assertElementDoesNotExist(
                Page.getTokenOptionContainingText(cryptoTokenName),
                cryptoTokenName + " was found on 'Crypto Tokens' page."
        );
    }
    
    /**
     * Checks that a given CryptoToken exists in the table of available tokens.
     * 
     * @param cryptoTokenName the name of the CryptoToken to check for.
     */
    public void assertTokenExists(String cryptoTokenName) {
        assertElementExists(
                Page.getTokenOptionContainingText(cryptoTokenName),
                cryptoTokenName + " was not found on 'Crypto Tokens' page."
        );
    }
    
    /**
     * Clicks the 'Test' button for the correct key name. 
     *
     * @param name The name of the key name.
     * @throws Exception If name doesn't exist.
     */
    public void clickTestKryptoToken(String name) {
        WebElement web = findElement(By.xpath("//form[@id='j_idt153']//td[contains(text(),'"+name+"')]/following-sibling::td/input[@value='Test']"));
        if(By.xpath("//form[@id='j_idt153']//td[contains(text(),'"+name+"')]") != null) {
            web.click();
        }
        else {
            fail("No key with name "+name+" exist");
        }
    }
    
    /**
     * Clicks the 'Remove' button for the correct key name. 
     *
     * @param name The name of the key name.
     * @throws Exception If name doesn't exist.
     */
    public void clickRemoveKey(String name) {
        WebElement keyTestButton = findElement(By.xpath("//form[@id='j_idt153']//td[contains(text(),'"+name+"')]/following-sibling::td/input[@value='Remove']"));
        if(By.xpath("//form[@id='j_idt153']//td[contains(text(),'"+name+"')]") != null) {
        keyTestButton.click();
        }else {
            fail("No key with name "+name+" exist");
        }
    }
    
    /**
     * Accepts alert popup when removing token key.  
     *
     * @param name The name of the key name.
     */
    public void confirmRemoveKey(String name) {
        clickRemoveKey(name);
        assertAndConfirmAlertPopUp("Are you sure you want to remove this key?", true);
    }
  
    /**
     * Checks that tested key is successfull.  
     *
     * @param name The name of the key name.
     */
    public void confirmKeyTestedSuccessfully(String name) {
        assertInfoMessageAppears(""+name+" tested successfully.", ""+name+" successfully test message was not not found", ""+name+" successfully test message was not displayed");
    }
    
    /**
     * Views the 'Crypto Token' with the certian name.
     *
     * @param name The name of the Token.
     */
    public void viewCryptoTokenWithName(String name) {
       clickLink(By.xpath("//form[@id=\"cryptotokens\"]/table/tbody/tr/td/a/span[contains(text(),'"+name+"')]"));
    }
}
