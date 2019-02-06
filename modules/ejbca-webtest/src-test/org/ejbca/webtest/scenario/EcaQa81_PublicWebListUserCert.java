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
package org.ejbca.webtest.scenario;

import org.ejbca.webtest.WebTestBase;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

import java.util.List;

import static org.junit.Assert.*;

/**
 * 
 * @version $Id$
 */
public class EcaQa81_PublicWebListUserCert extends WebTestBase {

    private static WebDriver webDriver;
    
    private static final String LISTCERT_URL = "/retrieve/list_certs.jsp";
    private static final String FETCHCACERT_URL = "/retrieve/ca_certs.jsp";

    @BeforeClass
    public static void init() {
        beforeClass(false, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() {
        webDriver.quit();
    }

    @Test
    public void testCertListing() {
        webDriver.get(getPublicWebUrl() + LISTCERT_URL);
        WebElement title = webDriver.findElement(By.xpath("//h1[@class='title']"));
        WebElement okButton = webDriver.findElement(By.id("ok"));
        okButton.click();

        title = webDriver.findElement(By.xpath("//h1[@class='title']"));
        assertEquals("No subject", title.getText());
        WebElement backLink = webDriver.findElement(By.xpath("//a[@href='list_certs.jsp']"));
        backLink.click();

        WebElement subjectDnField = webDriver.findElement(By.id("subject"));
        subjectDnField.sendKeys("CN=NonExistensSubjectDN");
        okButton = webDriver.findElement(By.id("ok"));
        okButton.click();

        title = webDriver.findElement(By.xpath("//h1[@class='title']"));
        assertEquals(title.getText(), "Certificates for CN=NonExistensSubjectDN");

        webDriver.get(getPublicWebUrl() + FETCHCACERT_URL);
        String firstCAName = webDriver.findElement(By.xpath("//div[@class='content']/div/div/p")).getText();
        assertTrue("Could not determine subject DN of CA", firstCAName.startsWith("CN="));

        webDriver.get(getPublicWebUrl() + LISTCERT_URL);
        subjectDnField = webDriver.findElement(By.id("subject"));
        subjectDnField.sendKeys(firstCAName);
        okButton = webDriver.findElement(By.id("ok"));
        okButton.click();

        title = webDriver.findElement(By.xpath("//h1[@class='title']"));
        String result = webDriver.findElement(By.xpath("//div[@class='content']/pre")).getText();
        List<WebElement> resultLinks = webDriver.findElements(By.xpath("//div[@class='content']/p/a"));
        assertEquals("Unexpected page title", "Certificates for " + firstCAName, title.getText());
        assertTrue("Missing attribute from cert listing result", result.contains("Subject:"));
        assertTrue("Missing attribute from cert listing result", result.contains("Issuer:"));
        assertTrue("Missing attribute from cert listing result", result.contains("NotBefore:"));
        assertTrue("Missing attribute from cert listing result", result.contains("NotAfter:"));
        assertTrue("Missing attribute from cert listing result", result.contains("Serial number:"));
        assertTrue("Missing attribute from cert listing result", result.contains("SHA1 fingerprint:"));
        assertTrue("Missing attribute from cert listing result", result.contains("SHA256 fingerprint:"));
        assertEquals("","Download certificate", resultLinks.get(0).getText());
        assertEquals("","Check if certificate is revoked", resultLinks.get(1).getText());
        // Checking the download popups requires some firefox profile settings (through webdriver)
        resultLinks.get(1).click();

        title = webDriver.findElement(By.xpath("//h1[@class='title']"));
        String revocationResultText = webDriver.findElement(By.xpath("//div[@class='content']")).getText();
        assertTrue("Missing attribute from certificate status", revocationResultText.contains("Issuer:"));
        assertTrue("Missing attribute from certificate status", revocationResultText.contains("Serial number:"));
        assertTrue("Unexpected revocation status", revocationResultText.contains("The certificate has NOT been revoked."));

    }

}
