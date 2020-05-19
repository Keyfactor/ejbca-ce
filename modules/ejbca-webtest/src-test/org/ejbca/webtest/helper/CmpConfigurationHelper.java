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

        /** Input field for alias name */
        static final By INPUT_NAME = By.id("cmpaliasesform:textfielcmpaliasname");

        /** List of available CMP aliases */
        static final By SELECT_ALIAS = By.id("cmpaliasesform:selectaliaslist");

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
     * Asserts the list of available CMP aliases in the Admin GUI contains the specified alias.
     * 
     * @param alias to check for
     */
    public void assertCmpAliasExists(final String alias) {
        final List<String> selectNames = getSelectNames(Page.SELECT_ALIAS);
        assertTrue("CMP alias '" +  alias  + "' was not found in the list of CMP aliases", selectNames.contains(alias));
    }
}
