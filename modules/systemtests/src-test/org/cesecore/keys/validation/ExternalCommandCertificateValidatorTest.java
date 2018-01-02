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

package org.cesecore.keys.validation;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.Test;

/**
 * This class contains whitebox integrations tests for External Command Validators. To determine whether
 * an external command was executed as specified we need to place a file on the fileystem in the location
 * given by the value mapped to the key <code>EXTERNAL_COMMAND</code>, or if we only care about whether
 * the command was invoked, it suffices to ensure the executable does not exist and then check for an
 * <code>ExternalProcessException</code>.
 * @version $Id$
 */
public class ExternalCommandCertificateValidatorTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalCommandCertificateValidatorTest.class);

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }
    
    @Test
    public void testDisabledWhitelist() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        // Check validation of an external call with x.509 RSA public key while IssuancePhase#CERTIFICATE_VALIDATION phase.
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, createCert("C=Test,O=Test,OU=Test,CN=testDisabledWhitelist"), ExternalScriptsWhitelist.permitAll());
    }

    @Test
    public void testAllowedCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, createCert("C=Test,O=Test,OU=Test,CN=testAllowedCommand"), new ExternalScriptsWhitelist(path));
    }

    @Test
    public void testAllowedCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path + " param1 param2");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, createCert("C=Test,O=Test,OU=Test,CN=testAllowedCommandWithParameters"), new ExternalScriptsWhitelist(path));
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path + "/foo/forbidden");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist(path));
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path + "/foo/forbidden param1 param2");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsWhitelist(path));
    }
    
    /**
     * Gets the platform dependent full path of the file in the class path.
     * 
     * @param classpath the class path (or filename -> put inside resources directory).
     * @return the full path.
     */
    // Code duplication.
    private final String getFilePathFromClasspath(final String classpath) {
        final String fileSuffix = SystemUtils.IS_OS_WINDOWS ? ".bat" : ".sh";
        final String subFolder = SystemUtils.IS_OS_WINDOWS ? "windows" : "unix";
        final String path = "resources/platform/" + subFolder + "/" + classpath + fileSuffix;
        final String result = new File( KeyValidatorSessionTest.class.getClassLoader().getResource(path).getFile()).getPath();
        if (log.isDebugEnabled()) {
            log.debug("Get file path by class path: " + classpath + " - " + result);
        }
        return SystemUtils.IS_OS_WINDOWS ? result.replaceFirst("/", StringUtils.EMPTY) : result;
    }
    
    private final X509Certificate createCert(final String cn) throws Exception {
        KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert(
                cn, 365, null,
                keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true);
        return certificate;
    }
}
