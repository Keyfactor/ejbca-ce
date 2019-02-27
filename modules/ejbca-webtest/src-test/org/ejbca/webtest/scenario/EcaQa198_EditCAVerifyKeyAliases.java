package org.ejbca.webtest.scenario;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.WebDriver;

/**
 * The CA can be both edited and restored.  When a CA is restored,
 * the key alias values should restore correctly.
 *
 * @version $Id: EcaQa198_EditCAVerifyKeyAliases.java 30836 2019-02-22 09:09:09Z margaret_d_thomas $
 */

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EcaQa198_EditCAVerifyKeyAliases extends WebTestBase {

    private static WebDriver webDriver;
    // Helpers
    private static CaHelper caHelper;
    private static CryptoTokenHelper cryptoTokenHelper;
    private static CommandLineHelper commandLineHelper = new CommandLineHelper();
    private static final String deleteAlert = "Are you sure you want to delete the CA " + EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME + "? You should revoke the CA instead if you already have used it to issue certificates.";


    // Test Data
    private static class TestData {
        static final String CA_NAME = "StatedumpExportTest";
        private static final String CA_VALIDITY = "1y";
        static final String TEXT_CA_RENEWAL_ALERT_MESSAGE = "Are you sure you want to renew this CA?";
        static final String TEXT_CA_RENEWAL_SUCCESS_MESSAGE = "CA Renewed Successfully";
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
    public static void exit() throws AuthorizationDeniedException {
        // Remove generated artifacts
        removeCaAndCryptoToken(EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME);
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
    public void stepC_createCAUsingCryptoToken() {
        //Verify CA using cryptotoken exists
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa("StatedumpExportTest");
        caHelper.setValidity(EcaQa198_EditCAVerifyKeyAliases.TestData.CA_VALIDITY);
        caHelper.setCryptoToken("ManagementCA");
        caHelper.createCa();
    }

    @Test
    public void stepD_buildStatedump() {
        //Run the designated ant command
        Assert.assertTrue(commandLineHelper.runCommand("ant statedump"));
        //To Do
        //Add File lines to check the creation of the directory
    }

    @Test
    public void stepE_exportCAssertStatedump() {
        //Export the CA
        //To Do
        commandLineHelper.runCommand("");
    }

    @Test
    public void stepF_deleteCA() {
        //Remove the CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCaAndAssert(deleteAlert, false, null, EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME);
    }

    @Test
    public void stepG_importCA() {
        //Reimport the CA
        caHelper.openPage(getAdminWebUrl());
        //To Do
        commandLineHelper.runCommand("{$ejbca_home}/dist/statedump/statedump.sh export -l eca-7758-statedump --exclude '*:*' --include='CA:StatedumpExportTest'");
    }

    @Test
    public void stepH_editCA() {
        //Edit the reimported CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit("StatedumpExportTest");
    }

    @Test
    public void stepI_assertKeyAliasesRestored() {
        //Assert Key values are restored.
        caHelper.assertCertSignKeyValue("defaultKey");
        caHelper.assertCertSignKeyValue("testKey");
        caHelper.assertCertSignKeyValue("signKey");
    }

}
