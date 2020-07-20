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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * This test verifies that renaming an Acme alias works.
 * <br/>
 * Reference: <a href="https://jira.primekey.se/browse/ECAQA-184">ECAQA-184</a>
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa184_RenameACMEAlias extends WebTestBase {
    //Helpers
    private static AcmeHelper acmeHelper;

    //Test Data
    public static class TestData {
        private static final String INITIAL_ACME_ALIAS = "EcaQa184TestAlias";
        private static final String RENAMED_ACME_ALIAS = "EcaQa184RenamedTestAlias";
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
    public void stepA_AddAlias() {
        acmeHelper.openPage(getAdminWebUrl());
        acmeHelper.clickAdd();
        acmeHelper.alertTextfieldAndAccept(TestData.INITIAL_ACME_ALIAS);
    }

    @Test
    public void stepB_RenameAlias() {
        acmeHelper.rename(TestData.INITIAL_ACME_ALIAS);
        acmeHelper.alertTextfieldAndAccept(TestData.RENAMED_ACME_ALIAS);
    }

    @Test
    public void stepC_RenameAliasAgain() {
        acmeHelper.rename(TestData.RENAMED_ACME_ALIAS);
        acmeHelper.alertTextfieldAndAccept(TestData.RENAMED_ACME_ALIAS);
        acmeHelper.confirmRenamedAliasAlreadyExists(TestData.RENAMED_ACME_ALIAS);
    }

    @Test
    public void stepD_RenameAliasEmpty() {
        acmeHelper.rename(TestData.RENAMED_ACME_ALIAS);
        acmeHelper.alertTextfieldAndAccept("");
        acmeHelper.confirmRenamedAliasAlreadyExists(TestData.RENAMED_ACME_ALIAS);
    }

    @Test
    public void stepE_DeleteAlias() {
        acmeHelper.deleteWithName(TestData.RENAMED_ACME_ALIAS);
    }
}