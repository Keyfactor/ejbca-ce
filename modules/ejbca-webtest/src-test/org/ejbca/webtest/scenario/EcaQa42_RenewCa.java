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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

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
import org.ejbca.webtest.helper.WebTestHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

/**
 * CAs can be renewed in different ways, only the CA certificate can be renewed
 * using the same keys or both the CA keys and the certificate can be renewed.
 * In this test case both scenarios are tested.
 * 
 * @version $Id: EcaQa42_RenewCa.java 30018 2018-10-04 15:31:01Z andrey_s_helmes $
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa42_RenewCa extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private static final String caName = "CA ECAQA42";

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

//    @Test
//    public void a_addCa() {
//        CaHelper.goTo(webDriver, getAdminWebUrl());
//        CaHelper.add(webDriver, caName);
//        CaHelper.setValidity(webDriver, "1y");
//        CaHelper.save(webDriver);
//        CaHelper.assertExists(webDriver, caName);
//    }

//    @Test
//    public void b_renewWithOldKeys() {
//        AuditLogHelper.resetFilterTime();
//        CaHelper.edit(webDriver, caName);
//        assertEquals("", "signKey", new Select(webDriver.findElement(By.xpath("//select[@name='selectcertsignkeyrenew']"))).getFirstSelectedOption().getText());
//        renewCa();
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.assertEntry(webDriver, "CA Renewal", "Success", caName, null);
//    }

//    @Test
//    public void c_renewWithNewKeys() {
//        AuditLogHelper.resetFilterTime();
//        CaHelper.goTo(webDriver, getAdminWebUrl());
//        CaHelper.edit(webDriver, caName);
//        new Select(webDriver.findElement(By.xpath("//select[@name='selectcertsignkeyrenew']"))).selectByVisibleText("– Generate new key using KeySequence –");
//        renewCa();
//    }

//    @Test
//    public void d_checkNewKeys() {
//        CaHelper.edit(webDriver, caName);
//        assertEquals("Unexpected value for certSignKey", "signKey00001", webDriver.findElement(By.xpath("//td[text()='certSignKey']//following-sibling::td")).getText());
//        assertEquals("Unexpected value for crlSignKey", "signKey00001", webDriver.findElement(By.xpath("//td[text()='crlSignKey']//following-sibling::td")).getText());
//        assertEquals("Unexpected value for Key sequence", "00001", webDriver.findElement(By.xpath("//input[@name='textfieldkeysequence']")).getAttribute("value"));
//
//        // Verify Audit Log
//        AuditLogHelper.goTo(webDriver, getAdminWebUrl());
//        AuditLogHelper.assertEntry(webDriver, "Crypto Token Key Pair Generate", "Success", null, null);
//        AuditLogHelper.assertEntry(webDriver, "CA Renewal", "Success", caName, null);
//    }

//    /**
//     * Clicks the 'Renew CA' button and checks that the renewal was successful
//     */
//    private void renewCa() {
//        webDriver.findElement(By.xpath("//input[@name='buttonrenewca']")).click();
//        WebTestHelper.assertAlert(webDriver, "Are you sure you want to renew this CA?", true);
//        try {
//            webDriver.findElement(By.xpath("//td[text()='CA Renewed Successfully']"));
//        } catch (NoSuchElementException e) {
//            fail("CA not renewed successfully");
//        }
//        CaHelper.assertExists(webDriver, caName);
//    }
}
