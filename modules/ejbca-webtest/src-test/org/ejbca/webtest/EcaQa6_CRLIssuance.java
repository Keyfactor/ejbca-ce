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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.AuditLogHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;

/**
 * This test aims is to create CRLs and download CRLs and check if these operations are successful.
 * A new CA should always issue an (empty) CRL. This is done when the CA is created.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa6_CRLIssuance extends WebTestBase {
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private static final String caName = "TestCA";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        int caId = caSessionRemote.getCAInfo(admin, caName).getCAId();
        int ctId = cryptoTokenManagementSessionRemote.getIdFromName(caName);
        caSessionRemote.removeCA(admin, caId);
        cryptoTokenManagementSessionRemote.deleteCryptoToken(admin, ctId);
        webDriver.quit();
    }

    @Test
    public void testA_addCA() {
        AuditLogHelper.resetFilterTime();

        // Add CA
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.add(webDriver, caName);
        CaHelper.setValidity(webDriver, "1y");
        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, caName);

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "CRL Store", "Success", null,
                Arrays.asList("Stored CRL with CRLNumber=", ", fingerprint=", ", issuerDN 'CN=" + caName + "'."));
        AuditLogHelper.assertEntry(webDriver, "CRL Create", "Success", null,
                Arrays.asList("Created CRL with number ", " for CA '" + caName + "' with DN 'CN=" + caName + "'."));
    }

    @Test
    public void testB_crl() {
        AuditLogHelper.resetFilterTime();

        // Go to 'CA Structure & CRLs'
        webDriver.get(getAdminWebUrl());
        webDriver.findElement(By.xpath("//li/a[contains(@href, 'cafunctions.xhtml')]")).click();

        // Verify that the 'Get CRL' link works
        String crlUrl = webDriver.findElement(By.xpath("//a[text()='Get CRL' and contains(@href, '" + caName + "')]")).getAttribute("href");
        webDriver.get("view-source:" + crlUrl);
        try {
            webDriver.findElement(By.xpath("//pre[contains(text(), '" + caName + "')]"));
        } catch (NoSuchElementException e) {
            fail("The CRL didn't contain the CA's name.");
        }

        // Go to 'CA Structure & CRLs'
        webDriver.get(getAdminWebUrl());
        webDriver.findElement(By.xpath("//li/a[contains(@href, 'cafunctions.xhtml')]")).click();

        // Take note of the CRL number
        String crlText = StringUtils.substringBetween(webDriver.findElement(By.xpath("//div[@class='container']")).getText(), caName, " Get CRL");
        int crlNumber = Integer.parseInt(StringUtils.substringAfter(crlText, "number "));

        // Click 'Create CRL' button
        webDriver.findElement(By.xpath(
                "//i[a[text() = 'Get CRL' and contains(@href, '" + caName + "')]]/following-sibling::form/input[contains(@name, 'buttoncreatecrl')]")).click();

        // Make sure that the CRL number has been incremented
        crlText = StringUtils.substringBetween(webDriver.findElement(By.xpath("//div[@class='container']")).getText(), caName, " Get CRL");
        assertEquals("The CRL number was not incremented.", crlNumber + 1, Integer.parseInt(StringUtils.substringAfter(crlText, "number ")));

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "CRL Store", "Success", null,
                Arrays.asList("Stored CRL with CRLNumber=", ", fingerprint=", ", issuerDN 'CN=" + caName + "'."));
        AuditLogHelper.assertEntry(webDriver, "CRL Create", "Success", null,
                Arrays.asList("Created CRL with number ", " for CA '" + caName + "' with DN 'CN=" + caName + "'."));
    }
}