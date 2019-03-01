package org.ejbca.webtest.scenario;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.webtest.WebTestBase;
import org.ejbca.webtest.helper.CaHelper;
import org.ejbca.webtest.helper.CryptoTokenHelper;
import org.ejbca.webtest.utils.CommandLineHelper;
import org.ejbca.webtest.utils.RemoveDir;
import org.junit.*;
import org.junit.runners.MethodSorters;
import org.openqa.selenium.Keys;
import org.openqa.selenium.WebDriver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

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
        private static final String EJBCA_HOME = System.getenv("EJBCA_HOME");
        static final String CA_NAME = "StatedumpExportTest";
        private static final String CA_VALIDITY = "1y";
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
    public void stepB_createCAUsingCryptoToken() {
        //Verify CA using cryptotoken exists
        caHelper.openPage(getAdminWebUrl());
        caHelper.addCa(TestData.CA_NAME);
        caHelper.setValidity(EcaQa198_EditCAVerifyKeyAliases.TestData.CA_VALIDITY);
        caHelper.createCa();
        caHelper.assertExists(EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME);

    }

    @Test(timeout=20000)
    public void stepC_buildStatedump() {
        //Run the designated ant command
        Assert.assertTrue(commandLineHelper.runCommand("ant statedump"));

        //Verify statedump directory created
        File statedumpDir = new File("dist/statedump");
        Assert.assertTrue(statedumpDir.exists());
    }

    @Test(timeout=20000)
    public void stepD_exportCAssertStatedump() {
        //Export the CA
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh export -l test-statedump --exclude '*:*' --include='CA:StatedumpExportTest'");

        //Verify exported CA directory created
        File dumpCaDir = new File("test-statedump");
        Assert.assertTrue(dumpCaDir.exists());
    }


    @Test(timeout=20000)
    public void stepE_importCA() {
        //Reimport the CA
        caHelper.openPage(getAdminWebUrl());
        commandLineHelper.runCommand("sh dist/statedump/statedump.sh import -l test-statedump");
    }

    @Test
    public void stepF_editCA() {
        //Edit the reimported CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.edit(TestData.CA_NAME);
    }


    @Test
    public void stepG_assertKeyAliasesRestored() {
        //Assert Key values are restored.
        caHelper.assertCrlSignKeyValue("signKey");
        caHelper.assertDefaultKeyValue("defaultKey");
        caHelper.assertTestKeyValue("testKey");
    }


    @Test
    public void stepH_deleteCA() {
        //Remove the CA
        caHelper.openPage(getAdminWebUrl());
        caHelper.deleteCaAndAssert(deleteAlert, false, null, EcaQa198_EditCAVerifyKeyAliases.TestData.CA_NAME);
    }

    @Test(timeout=10000)
    public void stepI_cleanDumps() throws IOException {
        //Remove statedump module and test statedump
        new RemoveDir("test-statedump").deleteDirectoryStream();
        new RemoveDir("dist/statedump").deleteDirectoryStream();
    }

}
