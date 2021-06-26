package org.ejbca.webtest.helper;

import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

import java.util.List;

import static org.junit.Assert.assertTrue;

/**
 * CMP Configuration helper class for EJBCA Web Tests.
 * 
 * @version $Id$
 *
 */
public class CmpConfigurationHelper extends BaseHelper {

    
    /**
     * Contains constants and references of the 'CMP configuration' page.
     */
    public static class Page {
        static final String PAGE_URI = "/ejbca/adminweb/sysconfig/cmpaliases.xhtml";
        static final By PAGE_LINK = By.id("sysConfigCmp");
        
        static final By BUTTON_ADD = By.id("cmpaliasesform:buttonaddcmpalias");
        static final By BUTTON_RENAME = By.id("cmpaliasesform:buttonrenamecmpalias");
        static final By BUTTON_CLONE = By.id("cmpaliasesform:buttonclonecmpalias");
        static final By BUTTON_EDIT = By.id("cmpaliasesform:buttoneditcmpalias");
        static final By BUTTON_DELETE = By.id("cmpaliasesform:buttondeletecmpalias");
        
        static final By BUTTON_CANCEL_DELETE = By.id("cmpaliasesform:buttoncanceldeletecmpalias");
        static final By BUTTON_CONFIRM_DELETE = By.id("cmpaliasesform:buttonconfirmdeletecmpalias");

        /** Input field for alias name */
        static final By INPUT_NAME = By.id("cmpaliasesform:textfielcmpaliasname");

        /** List of available CMP aliases */
        static final By SELECT_ALIAS = By.id("cmpaliasesform:selectaliaslist");
        
        /** Editing the alias */
        static final By SELECT_DEFAULT_CA = By.id("editcmpaliasform:cmpdefaultca");
        static final By BUTTON_CANCEL_ALIAS_EDIT = By.id("editcmpaliasform:cancelbutton");
        static final By BUTTON_SAVE_ALIAS_EDIT = By.id("editcmpaliasform:savebutton");
    }
    
    public CmpConfigurationHelper(final WebDriver webDriver) {
        super(webDriver);
    }
    
    /**
     * Opens the page 'CMP Configuration' by clicking menu link on home page and asserts the correctness of resulting URI.
     *
     * @param webUrl home page URL.
     */
    public void openPage(final String webUrl) {
        openPageByLinkAndAssert(webUrl, Page.PAGE_LINK, Page.PAGE_URI);
    }
    
    /**
     * Adds a CMP alias by filling in the alias name text field and clicking the 'Add' button
     * 
     * @param alias name of the alias to add
     */
    public void addCmpAlias(final String alias) {
        fillInput(Page.INPUT_NAME, alias);
        clickLink(Page.BUTTON_ADD);
    }
    
    /**
     * Edits a CMP alias by selecting it and clicking the 'Edit CMP Alias' button
     * 
     * @param alias name of the alias to edit
     */
    public void editCmpAlias(final String alias) {
        selectOptionByName(Page.SELECT_ALIAS, alias);
        clickLink(Page.BUTTON_EDIT);
    }
    
    /**
     * Initiates deletion of a CMP alias by selecting it and clicking the 'Delete CMP Alias' button
     * 
     * @param alias name of the alias to delete
     */
    public void deleteCmpAlias(final String alias) {
        selectOptionByName(Page.SELECT_ALIAS, alias);
        clickLink(Page.BUTTON_DELETE);
    }
    
    /**
     * Confirms deletion of a CMP alias by clicking the 'Confirm deletion' button
     */
    public void confirmDeleteCmpAlias() {
        clickLink(Page.BUTTON_CONFIRM_DELETE);
    }
    
    /**
     * Cancels deletion of a CMP alias by clicking the 'Cancel' button
     */
    public void cancelDeleteCmpAlias() {
        clickLink(Page.BUTTON_CANCEL_DELETE);
    }

    /**
     * Renames a CMP alias by selecting it from the list of available aliases, filling the alias name text field
     * and clicking on the 'Rename' button
     * 
     * @param oldAlias name of the alias to rename
     * @param newAlias new name of the alias
     */
    public void renameCmpAlias(final String oldAlias, final String newAlias) {
        selectOptionByName(Page.SELECT_ALIAS, oldAlias);
        fillInput(Page.INPUT_NAME, newAlias);
        clickLink(Page.BUTTON_RENAME);
    }

    /**
     * Clones a CMP alias by selecting an alias from
     * the list of available aliases, filling the alias name
     * text field and clicking on the 'Clone' button
     *
     * @param oldAlias name of the alias to rename
     * @param cloneAlias name of the cloned alias
     */
    public void cloneCmpAlias(final String oldAlias ,final String cloneAlias) {
        selectOptionByName(Page.SELECT_ALIAS, oldAlias);
        fillInput(Page.INPUT_NAME, cloneAlias);
        clickLink(Page.BUTTON_CLONE);
    }
    
    /**
     * Selects a default CA as specified by the input parameter
     * 
     * @param caName name of the CA to set as default
     */
    public void selectDefaultCA(final String caName) {
        selectOptionByName(Page.SELECT_DEFAULT_CA, caName);
    }
    
    /**
     * Cancels editing the CMP alias by clicking the 'Cancel' button
     */
    public void cancelEditCmpAlias() {
        clickLink(Page.BUTTON_CANCEL_ALIAS_EDIT);
    }
    
    /**
     * Saves the CMP alias by clicking the 'Save' button
     */
    public void saveEditCmpAlias() {
        clickLink(Page.BUTTON_SAVE_ALIAS_EDIT);
    }
    
    /**
     * Asserts the the specified CA is set as default in the CMP alias.
     * 
     * @param caName CA to check for
     */
    public void assertCmpAliasDefaultCA(String caName) {
        final List<String> selectedDefaultCAs = getSelectSelectedNames(Page.SELECT_DEFAULT_CA);
        assertTrue("The the CA '" + caName + "' was not set as default in the CMP alias", selectedDefaultCAs.contains(caName));
    }
    
    /**
     * Asserts the list of available CMP aliases in the Admin GUI contains the specified alias.
     * 
     * @param alias to check for
     */
    public void assertCmpAliasExists(final String alias) {
        final List<String> selectNames = getSelectNames(Page.SELECT_ALIAS);
        assertTrue("CMP alias '" +  alias  + "' was not found in the list of CMP aliases", selectNames.contains(alias));
    }
    
    /**
     * Asserts the list of available CMP aliases in the Admin GUI does not contain the specified alias.
     * 
     * @param alias to check for
     */
    public void assertCmpAliasDoesNotExist(final String alias) {
        final List<String> selectNames = getSelectNames(Page.SELECT_ALIAS);
        assertTrue("CMP alias '" +  alias  + "' was not found in the list of CMP aliases", !selectNames.contains(alias));
    }
}
