/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

/**
 * Test class fot RSA key validator functional methods, see {@link RsaKeyValidator}.
 * 
 * @version $Id: EccKeyValidatorTest.java 26242 2017-08-08 09:53:27Z anatom $
 */
package org.cesecore.keys.validation;

import static org.junit.Assert.assertTrue;

import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests ECC key validator functions.
 * 
 * @version $Id: ExternalCommandCertificateValidatorTest.java 26242 2017-11-11 12:07:27Z anatom $
 */
public class ExternalCommandCertificateValidatorTest {

    //    private static final Map<String, String> DEFAULT_PLATFORM_TEST_COMMANDS = new HashMap<String, String>();
    //
    //    static {
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("Windows", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("UNIX", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("LINUX", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("Linux", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("Solaris", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("AIX", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("HP-UX", "echo Hello");
    //        DEFAULT_PLATFORM_TEST_COMMANDS.put("Mac", "echo Hello");
    //    }

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalCommandCertificateValidatorTest.class);

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }

    @After
    public void tearDown() throws Exception {
        log.trace(">tearDown()");
        // NOOP
        log.trace("<tearDown()");
    }

    @Test
    public void test01BuildShellCommand() throws Exception {
        log.trace(">test01BuildShellCommand()");

        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        // 1. Test custom platform command (here: same as platform could not be detected).
        String cmd = ExternalCommandCertificateValidator.PLACE_HOLDER_CUSTOM_PLATFORM_COMMAND + " " + " echo (<<EOF "
                + ExternalCommandCertificateValidator.PLACE_HOLDER_CERTIFICATE + ")";
        validator.setExternalCommand(cmd);
        List<String> cmdList = validator.buildShellCommand();
        assertTrue("A custom platform command has no default platform shell and shell options.", cmdList.size() == 0);

        // 2. Test platform dependent command (if this test fails, please update the code to fit the platform, see {@link ExternalCommandCertificateValidator.buildShellCommand}).
        cmd = "echo " + ExternalCommandCertificateValidator.PLACE_HOLDER_CERTIFICATE + " | openssl x509 -text -noout";
        validator.setExternalCommand(cmd);
        cmdList = validator.buildShellCommand();
        assertTrue("Platform must have been detected and platform shell and shell options are set and command is added: " + cmdList,
                cmdList.size() == 3);

        log.trace(">test01BuildShellCommand()");
    }

    @Test
    public void test02BuildPlatformCommand() throws Exception {
        log.trace(">test02BuildPlatformCommand()");

        // 1. Test platform command with %cert% place holder (see {@link ExternalCommandCertificateValidator.PLACE_HOLDER_CERTIFICATE}).
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        String cmd = "echo " + ExternalCommandCertificateValidator.PLACE_HOLDER_CERTIFICATE + " | openssl x509 -text -noout";
        validator.setExternalCommand(cmd);
        List<String> cmdList = validator.buildShellCommand();
        assertTrue("Platform must have been detected and platform shell and shell options are set and command is added: " + cmdList.size(),
                cmdList.size() == 3);
        // ECA-6951 Test: Impl. assert

        log.trace(">test02BuildPlatformCommand()");
    }

    @Test
    public void test03LaunchExternalCommand() throws Exception {
        log.trace(">test03LaunchExternalCommand()");

        // 1. Test simple echo "Hello World" command.
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        String cmd = "echo \"Hello World\"";
        validator.setExternalCommand(cmd);
        List<String> cmdList = validator.buildShellCommand();
        List<String> out = validator.launchExternalCommand(cmdList.toArray(new String[] {}), true, true);
        assertTrue("Exit code of echo command should be 0: " + out, out != null && out.size() > 0
                && Integer.parseInt(out.get(0).replaceAll(ExternalCommandCertificateValidator.EXIT_CODE_PREFIX, StringUtils.EMPTY)) == 0);
        // ECA-6951 Test: Impl. assert

        // 2. Test not existing command.
        cmd = "kjuurzz5quark";
        validator.setExternalCommand(cmd);
        cmdList = validator.buildShellCommand();
        out = validator.launchExternalCommand(cmdList.toArray(new String[] {}), true, true);
        log.info(out);
        assertTrue("Exit code of not existing command " + cmd + " should be > 0: " + out, out != null && out.size() > 0
                && Integer.parseInt(out.get(0).replaceAll(ExternalCommandCertificateValidator.EXIT_CODE_PREFIX, StringUtils.EMPTY)) > 0);

        log.trace(">test03LaunchExternalCommand()");
    }

    //    @Test
    //    public void testCertificateValidationWithExternalCommand() throws Exception {
    //        log.trace(">testCertificateValidationWithExternalCommand()");
    //
    //        // Test ECC key validation OK with an allowed curve.
    //        KeyPair keys = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_ECDSA);
    //        EccKeyValidator keyValidator = (EccKeyValidator) KeyValidatorTestUtil.createKeyValidator(EccKeyValidator.class,
    //                "ecc-parameter-validation-test-1", "Description", null, -1, null, -1, -1, new Integer[] {});
    //        keyValidator.setSettingsTemplate(KeyValidatorSettingsTemplate.USE_CUSTOM_SETTINGS.getOption());
    //        // Set custom curve
    //        List<String> curves = new ArrayList<String>();
    //        curves.add("secp256r1");
    //        keyValidator.setCurves(curves);
    //        List<String> messages = keyValidator.validate(keys.getPublic(), null);
    //        log.trace("Key validation error messages: " + messages);
    //        assertTrue("Key valildation should have been successful.", messages.size() == 0);
    //        // Set custom curve to something else, so it's not supported
    //        curves.clear();
    //        curves.add("secp384r1");
    //        keyValidator.setCurves(curves);
    //        messages = keyValidator.validate(keys.getPublic(), null);
    //        log.trace("Key validation error messages: " + messages);
    //        assertTrue("Key validation should have failed.", messages.size() > 0);
    //        assertEquals("Key valildation should have failed.",
    //                "Invalid: ECDSA curve [secp256r1, prime256v1, P-256]: Use one of the following [secp384r1].", messages.get(0));
    //
    //        // TODO: create some failed EC key to test validation on
    //        log.trace("<testCertificateValidationWithExternalCommand()");
    //    }
}
