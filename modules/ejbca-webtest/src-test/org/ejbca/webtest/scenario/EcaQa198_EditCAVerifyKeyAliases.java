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

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.ejbca.webtest.utils.RemoveDir;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;


/**
 * The CA can be both edited and restored.  When a CA is restored,
 * the key alias values should restore correctly.
 *
 * @version $Id$
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa198_EditCAVerifyKeyAliases extends WebTestBase {

    private static final int TIMEOUT = 60000;
    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;
    private static CommandLineHelper commandLineHelper = new CommandLineHelper();
    private static final String deleteAlert = "Are you sure you want to delete the CA " + TestData.CA_NAME + "? You should revoke the CA instead if you already have used it to issue certificates.";


    // Test Data
    private static class TestData {
        private static final String CA_NAME = "StatedumpExportTest";
        private static final String CA_VALIDITY = "1y";
        private static final String STATUS_UNINITIALIZED = "Uninitialized";
    }

    @BeforeClass
    public static void init() {
        // super
        beforeClass(true, null);
        webDriver = getWebDriver();
        // Init helpers
        caHelper = new CaHelper(webDriver);
        cryptoTokenHelper = new CryptoTokenHelper(webDriver);
    }

    @AfterClass
    public static void exit() throws AuthorizationDeniedException, IOException {
        // Remove generated artifacts
        removeCaAndCryptoToken(EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME);
        new RemoveDir("test-statedump").deleteDirectoryStream();
        new RemoveDir("dist/statedump").deleteDirectoryStream();
        // super
        afterClass();
    }

    @Test
    public void stepA_assertCryptoTokenExists() {
        //Verify a cryptotoken exists
        cryptoTokenHelper.openPage(getAdminWebUrl());
        cryptoTokenHelper.assertTokenExists("ManagementCA");
    }

    @Test
    public void stepB_createCAUsingCryptoToken() {
        //Verify CA using cryptotoken exists
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(TestData.CA_NAME);

    }

    @Test(timeout=TIMEOUT)
    public void stepC_buildStatedump() {
        //Run the designated ant command
        Assert.assertTrue(commandLineHelper.runCommand("ant statedump"));

        //Verify statedump directory created
        final Path path = Paths.get("dist/statedump");
        Assert.assertTrue(Files.exists(path));
    }

    @Test(timeout=TIMEOUT)
    public void stepD_unlockStatedump() {
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh lockdown --unlock");
    }

    @Test(timeout=TIMEOUT)
    public void stepE_exportCAssertStatedumpCmdLine() {
        //Export the CA
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh export -l test-statedump --exclude '*:*' --include='CA:StatedumpExportTest'");

        //Verify exported CA directory created
        final Path path = Paths.get("test-statedump");
        Assert.assertTrue(Files.exists(path));
    }

    @Test
    public void stepF_deleteCA() {
        //Remove the CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCaAndAssert(deleteAlert, true, false, null, TestData.CA_NAME);
    }

    @Test(timeout=TIMEOUT)
    public void stepG_unlockStatedumpBeforeImport() {
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh lockdown --unlock");
    }


    @Test(timeout=TIMEOUT)
    public void stepH_importCACmdLine() {
        //Reimport the CA
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh import -l test-statedump");
    }

    @Test
    public void stepI_editCA_Initialize() {
        //Edit the reimported CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME, TestData.STATUS_UNINITIALIZED);
        caHelper.saveAndInitializeCa();
    }

    @Test
    public void stepJ_assertKeyAliasesRestored() {
        //Assert Key values are restored.
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
        caHelper.assertCrlSignKeyValue("signKey");
        caHelper.assertDefaultKeyValue("defaultKey");
        caHelper.assertTestKeyValue("testKey");
    }
}
