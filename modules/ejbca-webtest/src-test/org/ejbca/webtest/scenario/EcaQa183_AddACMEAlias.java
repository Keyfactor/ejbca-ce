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
import org.ejbca.webtest.helper.AcmeHelper;
import org.ejbca.webtest.junit.MemoryTrackingTestRunner;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;

/**
 * This test verfies that adding and deleting Acme alias works.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-183">ECAQA-183</a>
 * 
 * @version $Id$ EcaQa183_AddACMEAlias.java 2020-04-21 15:00 tobiasM$
 */
@RunWith(MemoryTrackingTestRunner.class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa183_AddACMEAlias extends WebTestBase {
    //Helpers
    private static AcmeHelper acmeHelper;

    //Test Data
    public static class TestData {
        private static final String ACME_ALIAS = "EcaQa183TestAlias";
    }

    @BeforeClass
    public static void init() {
        beforeClass(true, null);
        acmeHelper = new AcmeHelper(getWebDriver());
    }

    @AfterClass
    public static void exit() {
        afterClass();
    }

    @Test
    public void stepA_AddAcme() {
        acmeHelper.openPage(getAdminWebUrl());
        acmeHelper.clickAdd();
        acmeHelper.alertTextfieldAndAccept(TestData.ACME_ALIAS);
    }

    @Test
    public void stepB_AddSameAcmeAgain() {
        acmeHelper.clickAdd();
        acmeHelper.alertTextfieldAndAccept(TestData.ACME_ALIAS);
        acmeHelper.confirmAliasAlreadyExist(TestData.ACME_ALIAS);
    }

    @Test
    public void stepC_AddAcmeAliasWithoutName() {
        acmeHelper.clickAdd();
        acmeHelper.alertTextfieldAndAccept("");
    }

    @Test
    public void stepD_DeleteAcme() {
        acmeHelper.deleteWithName(TestData.ACME_ALIAS);
    }
}