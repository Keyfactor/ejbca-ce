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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.Select;

/**
 * Creates a self signed CVC CA using a dedicated Crypto Token.
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa3_LocallySignedCvcCa extends WebTestBase {

    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("EjbcaWebTest"));

    private static WebDriver webDriver;
    private static CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static CryptoTokenManagementSessionRemote cryptoTokenManagementSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);

    private static final String rootName = "ECAQA3";
    private static final String subName = "subCA ECAQA3";
    private static final String rootDn = "CN=ECAQA3,C=SE";
    private static final String subDn = "CN=subCA3,C=SE";

    @BeforeClass
    public static void init() {
        setUp(true, null);
        webDriver = getWebDriver();
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException {
        int rootId = caSessionRemote.getCAInfo(admin, rootName).getCAId();
        int subId = caSessionRemote.getCAInfo(admin, subName).getCAId();
        int ctId = cryptoTokenManagementSessionRemote.getIdFromName(rootName);
        caSessionRemote.removeCA(admin, rootId);
        caSessionRemote.removeCA(admin, subId);
        cryptoTokenManagementSessionRemote.deleteCryptoToken(admin, ctId);
        webDriver.quit();
    }

    @Test
    public void a_createRootCa() {
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.add(webDriver, rootName);

        // Set CA Type, Subject DN and Validity
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcatype']")))).selectByVisibleText("CVC");
        CaHelper.setSubjectDn(webDriver, rootDn);
        CaHelper.setValidity(webDriver, "1y");

        // Save the CA and check that save was successful
        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, rootName);
    }

    @Test
    public void b_checkCryptoToken() {
        CryptoTokenHelper.goTo(webDriver, getAdminWebUrl());
        CryptoTokenHelper.assertExists(webDriver, rootName);
    }

    @Test
    public void c_createSubCa() {
        CaHelper.goTo(webDriver, getAdminWebUrl());
        CaHelper.add(webDriver, subName);

        // Set CA Type, Crypto Token, Subject DN, Signed By, Validity and Certificate Profile
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcatype']")))).selectByVisibleText("CVC");
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcryptotoken']")))).selectByVisibleText(rootName);
        CaHelper.setSubjectDn(webDriver, subDn);
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectsignedby']")))).selectByVisibleText(rootName);
        CaHelper.setValidity(webDriver, "2y");
        (new Select(webDriver.findElement(By.xpath("//select[@name='selectcertificateprofile']")))).selectByVisibleText("SUBCA");

        // Save the CA and check that save was successful
        CaHelper.save(webDriver);
        CaHelper.assertExists(webDriver, subName);
    }
}