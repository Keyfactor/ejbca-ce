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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 * This class contains whitebox integrations tests for External Command Validators. To determine whether
 * an external command was executed as specified we need to place a file on the fileystem in the location
 * given by the value mapped to the key <code>EXTERNAL_COMMAND</code>, or if we only care about whether
 * the command was invoked, it suffices to ensure the executable does not exist and then check for an
 * <code>ExternalProcessException</code>. In ECCV this exception is re-thrown as <code>ValidatorNotApplicableException</code>. 
 * 
 * Make scripts executable, if not done with SVN extension!
 * 
 * chmod u+x $EJBCA_HOME/modules/systemtests/resources/platform/unix/*.sh
 * 
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
        validator.validate(null, createCert("C=Test,O=Test,OU=Test,CN=testDisabledWhitelist"), ExternalScriptsAllowlist.permitAll());
    }

    @Test
    public void testAllowedCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        final X509Certificate certificate = createCert("C=Test,O=Test,OU=Test,CN=testAllowedCommand");
        String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        
        // A: Let validation succeed. 
        // A.1 Sample script logs to error stream with failOnStandardError=false.
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(ExternalCommandCertificateValidator.FAIL_ON_STANDARD_ERROR, false);
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        List<String> out = validator.validate(null, certificate, new ExternalScriptsAllowlist(path));
        assertEquals("Validation with external script logged to ERROUT with failOnStandardError=false must succeed.", out.size(), 0);
        
        // B: Let validation fail (result list size > 0).
        // B.1 Sample script logs to error stream with failOnStandardError=true.
        data.put(ExternalCommandCertificateValidator.FAIL_ON_STANDARD_ERROR, true);
        validator.setDataMap(data);
        out = validator.validate(null, certificate, new ExternalScriptsAllowlist(path));
        assertTrue("Validation with external script logged to ERROUT with failOnStandardError=true must have failed.", out.size() > 0);
        log.info( "ECCV validation called with result: " + out);
        
//        Does not work as expected.
//        // B.2 Sample script logs to error stream with failOnStandardError=true but logStandardOut=false and logErrorOut=false.
//        data.put(ExternalCommandCertificateValidator.FAIL_ON_STANDARD_ERROR, true);
//        data.put(ExternalCommandCertificateValidator.LOG_STANDARD_OUT, false);
//        data.put(ExternalCommandCertificateValidator.LOG_ERROR_OUT, false);
//        validator.setDataMap(data);
//        out = validator.validate(null, certificate, new ExternalScriptsWhitelist(path));
//        assertTrue("Validation with external script logged to ERROUT with failOnStandardError=true but logStandardOut=false and logErrorOut=false must have failed as well.", out.size() > 0);
//        log.info( "ECCV validation called with result: " + out);
        
        // B.3 Sample scripts return code is larger than 0 with failOnStandardError=true.
        path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_1");
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(ExternalCommandCertificateValidator.FAIL_ON_STANDARD_ERROR, false);
        data.put(ExternalCommandCertificateValidator.FAIL_ON_ERROR_CODE, true);
        data.put(ExternalCommandCertificateValidator.LOG_STANDARD_OUT, true);
        data.put(ExternalCommandCertificateValidator.LOG_ERROR_OUT, true);
        validator.setDataMap(data);
        out = validator.validate(null, certificate, new ExternalScriptsAllowlist(path));
        assertTrue("Validation with external script logged to ERROUT with failOnStandardError=true must have failed.", out.size() > 0);
        log.info( "ECCV validation called with result: " + out);
        
        // B.4 Sample scripts return code is larger than 0 with failOnStandardError=true, logStandardOut=false and logErrorOut=false. 
        data.put(ExternalCommandCertificateValidator.LOG_STANDARD_OUT, false);
        data.put(ExternalCommandCertificateValidator.LOG_ERROR_OUT, false);
        validator.setDataMap(data);
        out = validator.validate(null, certificate, new ExternalScriptsAllowlist(path));
        assertTrue("Validation with external script logged to ERROUT with failOnStandardError=true, logStandardOut=false and logErrorOut=false must have failed as well.", out.size() > 0);
        log.info( "ECCV validation called with result: " + out);
    }

    @Test
    public void testAllowedCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path + " param1 param2");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        final List<String> out = validator.validate(null, createCert("C=Test,O=Test,OU=Test,CN=testAllowedCommandWithParameters"), new ExternalScriptsAllowlist(path));
        log.info( "External script called with result: " + out);
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommand() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsAllowlist(path + "/foo/doesnotexist"));
    }

    @Test(expected = ValidatorNotApplicableException.class)
    public void testForbiddenCommandWithParameters() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path + " param1 param2");
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsAllowlist(path + "/foo/doesnotexist"));
    }
    
    @Test(expected = ValidatorNotApplicableException.class)
    public void testCommandNotFound() throws Exception {
        final ExternalCommandCertificateValidator validator = new ExternalCommandCertificateValidator();
        final String path = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0") + "/foo/doesnotexist";
        final LinkedHashMap<Object, Object> data = new LinkedHashMap<>();
        data.put(ExternalCommandCertificateValidator.EXTERNAL_COMMAND, path);
        data.put(UpgradeableDataHashMap.VERSION, 1f);
        validator.setDataMap(data);
        validator.validate(null, null, new ExternalScriptsAllowlist(path));
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
        final String path = "platform/" + subFolder + "/" + classpath + fileSuffix;
        if (this.getClass().getClassLoader().getResource(path) == null) {
            throw new RuntimeException("Add modules/systemtests/resources to classpath.");
        }
        final String result = new File(this.getClass().getClassLoader().getResource(path).getFile()).getPath();
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
