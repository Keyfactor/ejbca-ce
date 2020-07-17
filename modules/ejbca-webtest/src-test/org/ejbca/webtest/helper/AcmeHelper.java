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

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;

/**
 * ACME helper class for EJBCA Web Tests.
 *
 *  @version $Id: AcmeHelper.java 2020-04-21 15:00 tobiasM$
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

        //Buttons
        static final By BUTTON_ADD_ALIAS = By.xpath("//a[@title='Add Alias']");
        static final By BUTTON_SAVE = By.id("acmeConfigs:save");
        static final By BUTTON_RENAME_ALIAS = By.xpath("//a[@title='Rename Alias']");
        static final By BUTTON_DELETE_ALIAS = By.xpath("//a[@title='Delete Alias']");

        //Dynamic Reference

        //  name - name of the Alias
        //  buttonName - Rename / Delete
        static By getActionsButton(String name, String buttonName) {
            return By.xpath("//a[@href='acmealiasconfiguration.xhtml?alias=" + name + "']/following::td/a[@title='" + buttonName + " Alias']");
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

}