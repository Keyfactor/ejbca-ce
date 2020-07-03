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
import org.openqa.selenium.WebElement;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 'Inspect Certificate CSR' helper class for EJBCA Web Tests.
 *
 * @version $Id: InspectCertificateCsrHelper.java 35074 2020-05-25 15:43:51Z margaret_d_thomas $
 */
public class InspectCertificateCsrHelper extends BaseHelper {

    /**
     * Inner class defining EJBCA PublicWeb Elements
     *
     */
    public static class Page {
        //Left Menu
        static final By MENU_LINK_INSPECT_CERTIFICATE_CSR = By.linkText("Inspect certificate/CSR");

        //Buttons
        static final By BUTTON_OK = By.id("ok");

        //Fields
        static final By INPUT_BROWSE_CERTIFICATE_UPLOAD = By.id("reqfile");

        //Labels
        static final By LABEL_CSR_DUMP_HEADER = By.cssSelector(".content > p:nth-child(3)");

        //Page Content
        static final By PAGE_CONTENT_CERTIFICATE_DUMP = By.cssSelector(".content > pre:nth-child(4)");
    }

    /**
     * Class constructor
     *
     * @param webDriver WebDriver
     */
    public InspectCertificateCsrHelper(final WebDriver webDriver) {
        super(webDriver);
    }

    /**
     * Click menu item Inspect Certificate/CSR
     *
     */
    public void clickInspectCertificateCSR() {
        clickLink(Page.MENU_LINK_INSPECT_CERTIFICATE_CSR);
    }

    /**
     * Selects and uploads a file.
     *
     * @param filename File to Upload.
     */
    public void setCertificateFile(String filename) {
        fillInput(Page.INPUT_BROWSE_CERTIFICATE_UPLOAD, filename);
    }

    /**
     * Click OK to upload file
     *
     */
    public void clickOK() {
        clickLink(Page.BUTTON_OK);
    }

    /**
     * Asserts uploaded filename is correct
     *
     * @param uploadMessage Incorrect file type message
     */
    public void assertCsrDumpHeader(String uploadMessage) {
        final WebElement certificateResults = findElement(Page.LABEL_CSR_DUMP_HEADER);
        assertEquals("Certificate file upload results is incorrect", uploadMessage,
                certificateResults.getText());
    }

    /**
     * Assert content is found in certificate dump
     *
     * @param content
     */
    public void assertCertificateContent(final String content) {
        Boolean found = true;
        String line = null;

        //Parse certificate in content to a list array
        List<String> certificateRows = new ArrayList<String>(Arrays.asList(content.split("\n")));

        //Get certificate contents from screen
        final WebElement certificateDump = findElement(Page.PAGE_CONTENT_CERTIFICATE_DUMP);
        String fileContents = certificateDump.getText();
        List<String> fileContentsList = new ArrayList<>(Arrays.asList(fileContents.split("\n")));

        //For each row in the array assert it exists in the fileContents
        for (String certificateRow : certificateRows) {
            line = certificateRow.trim();
            //System.out.println("Expected:  " + line);
            if (! (line.contains("Date:") || line.contains("Public Key:"))) {
                if (!fileContents.contains(line)) {
                    if (found) {
                        found = false;
                        break;
                    }
                }
            } else {
                System.out.println("Skipping verification:  " + line);
            }
        }

        assertEquals("Certificate file content is incorrect at line " + line, true,
                found);
    }
}
