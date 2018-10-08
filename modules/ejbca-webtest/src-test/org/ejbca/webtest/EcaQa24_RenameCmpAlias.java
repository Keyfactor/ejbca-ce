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
package org.ejbca.webtest;

import static org.junit.Assert.fail;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Alert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

/**
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa24_RenameCmpAlias extends WebTestBase {

    private static final String cmpAlias = "EcaQa24CmpAlias";
    private static final String cmpAliasRenamed = "EcaQa24CmpAliasNew";
    private static WebDriver webDriver;
    
    
    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }
    
    @AfterClass
    public static void exit() {
        webDriver.close();
    }
    
    /**
     * Adds the alias. No assertions here. It is prerequisites.
     */
    @Test
    public void testA_createCmpAlias() {
        webDriver.get(getAdminWebUrl());
        webDriver.findElement(By.xpath("//li/a[contains(@href,'cmpconfiguration.jsp')]")).click();
        webDriver.findElement(By.xpath("//input[@name='textfieldalias']")).sendKeys(cmpAlias);
        webDriver.findElement(By.xpath("//input[@name='buttonaliasadd']")).click();
    }
    
    @Test
    public void testB_renameCmpAlias() {
        Select selectAliasFromList = new Select(webDriver.findElement(By.xpath("//select[@name='selectaliases']")));
        selectAliasFromList.selectByVisibleText(cmpAlias);
        webDriver.findElement(By.xpath("//input[@name='textfieldalias']")).sendKeys(cmpAliasRenamed);
        webDriver.findElement(By.xpath("//input[@name='buttonaliasrename']")).click();
        
        selectAliasFromList = new Select(webDriver.findElement(By.xpath("//select[@name='selectaliases']")));
        try {
            selectAliasFromList.selectByVisibleText(cmpAliasRenamed);
        } catch (NoSuchElementException e) {
            fail("Could not find the renamed CMP Alias in the list of aliases");
        } finally {
            // Delete the alias
            webDriver.findElement(By.xpath("//input[@name='buttondeletealias']")).click();
            Alert alert = webDriver.switchTo().alert();
            alert.accept();
        }
    }
}