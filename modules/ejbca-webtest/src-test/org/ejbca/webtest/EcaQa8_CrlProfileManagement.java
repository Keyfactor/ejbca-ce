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

import java.util.Arrays;

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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * CRL profiles don't exist as independent entities, but are instead an inherent
 * part of CAs. Thus there are no dedicated CRL profile Audit Log statements,
 * instead modifying the CRL profile values within a CA will be logged under the
 * standard log statements for modifying CAs.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa8_CrlProfileManagement extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private static final String caName = "TestCRLCA";

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
    public void a_addCa() {
        AuditLogHelper.resetFilterTime();
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.add(webDriver, caName);
        CaHelper.setValidity(webDriver, "1y");

        // CRL settings
        WebElement crlExpirePeriod = webDriver.findElement(By.xpath("//input[@name='textfieldcrlperiod']"));
        WebElement crlIssueInterval = webDriver.findElement(By.xpath("//input[@name='textfieldcrlissueinterval']"));
        WebElement crlOverlapTime = webDriver.findElement(By.xpath("//input[@name='textfieldcrloverlaptime']"));
        crlExpirePeriod.clear();
        crlIssueInterval.clear();
        crlOverlapTime.clear();
        crlExpirePeriod.sendKeys("1d");
        crlIssueInterval.sendKeys("22h");
        crlOverlapTime.sendKeys("30m");

        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, caName);

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "CRL Create", "Success", caName, null);
        AuditLogHelper.assertEntry(webDriver, "CRL Store", "Success", caName, null);
        AuditLogHelper.assertEntry(webDriver, "Certificate Store", "Success", caName, null);
        AuditLogHelper.assertEntry(webDriver, "CA Edit", "Success", caName, null);
        AuditLogHelper.assertEntry(webDriver, "CA Create", "Success", caName, null);
    }

    @Test
    public void b_editCa() {
        AuditLogHelper.resetFilterTime();
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.edit(webDriver, caName);

        // Change 'CRL Issue Interval'
        WebElement crlIssueInterval = webDriver.findElement(By.xpath("//input[@name='textfieldcrlissueinterval']"));
        crlIssueInterval.clear();
        crlIssueInterval.sendKeys("20h");

        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, caName);

        // Verify Audit Log
        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
        AuditLogHelper.assertEntry(webDriver, "CA Edit", "Success", caName,
                Arrays.asList("msg=CA with id", "and name " + caName + " edited", "changed:crlIssueInterval=72000000"));
    }
}
