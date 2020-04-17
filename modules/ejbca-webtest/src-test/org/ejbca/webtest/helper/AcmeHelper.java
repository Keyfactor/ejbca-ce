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

import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * ACME helper class for EJBCA Web Tests.
 * 
 * @version
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
        static final By BUTTON_ADD = By.xpath("//a[@title='Add Alias']");
        static final By BUTTON_SAVE = By.id("acmeConfigs:save");
        static final By BUTTON_RENAME = By.xpath("//a[@title='Rename Alias']");
        static final By BUTTON_DELETE = By.xpath("//a[@title='Delete Alias']");
    }

    /**
     * Public constructor.
     *
     * @param webDriver web driver.
     */
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
     * Clicks the 'Add' button
     *
     */
    public void clickAdd() {
        clickLink(Page.BUTTON_ADD);
    }

    /**
     * Clicks the 'Rename' button for the correct Alias. 
     *
     * @param name The name of the Alias.
     */
    public void rename(String name) {
        WebElement renameButton = findElement(By.xpath("//a[@href='acmealiasconfiguration.xhtml?alias=" + name + "']/following::td/a[@title='Rename Alias']"));
        if (By.xpath("//form[@id='aliases']/table/tbody/tr/td[1]/a/span[@title='" + name + "']") != null) {
            renameButton.click();
        } else {
            fail("No Alias with that "+name+" exist");
        }
    }

    /**
     * Clicks the 'Delete' button for the correct Alias. 
     *
     * @param name The name of the Alias.
     */
    public void deleteWithName(String name) {
        WebElement deleteButton = findElement(By.xpath("//a[@href='acmealiasconfiguration.xhtml?alias=" + name + "']/following::td/a[@title='Delete Alias']"));
        if (By.xpath("//form[@id='aliases']/table/tbody/tr/td[1]/a/span[@title='" + name + "']") != null) {
            deleteButton.click();
        } else {
            fail("No Alias with that "+name+" exist");
        }
    }

    /**
     * Checks that ACME alias name already exist. 
     *
     *@param name The Alias name to check.
     */
    public void confirmAliasAlreadyExist(String name) {
        assertErrorMessageAppears(
                "Cannot add alias. Alias '" + name + "' already exists.", 
                "Cannot Add Alias error message was not found",
                "Expected Alias error message was not displayed");
    }

    /**
     * Switches to the alert window. 
     *
     */
    public Alert alertWindow() {
        Alert alert = webDriver.switchTo().alert();
        return alert;
    }

    /**
     * Accepts the alert. 
     *
     */
    public void acceptAlert() {
        alertWindow().accept();
    }
}