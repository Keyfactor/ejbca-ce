/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.Predicate;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.junit.Before;
import org.junit.Test;

/** Tests the external process tools static helper class.
 * 
 * @version $Id: ExternalProcessToolsTest.java 25133 2017-12-14 09:20:32Z anjakobs $
 */
public class ExternalProcessToolsTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalProcessToolsTest.class);

    @Before
    public void setUp() throws Exception {
        log.trace(">setUp()");
        CryptoProviderTools.installBCProvider();
        log.trace("<setUp()");
    }
    
    @Test
    public void buildShellCommand() throws Exception {
        log.trace(">buildShellCommand()");

        final String externalCommand = "help";
        final List<String> shellCommand = ExternalProcessTools.buildShellCommand(externalCommand);
        if (SystemUtils.IS_OS_WINDOWS) {
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell must be "
                    + ExternalProcessTools.WINDOWS_SHELL, shellCommand.get(0).equals(ExternalProcessTools.WINDOWS_SHELL));
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell options must be "
                    + ExternalProcessTools.WINDOWS_SHELL_OPTIONS, shellCommand.get(1).equals(ExternalProcessTools.WINDOWS_SHELL_OPTIONS));
        } else {
            // Add platforms here.
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell must be "
                    + ExternalProcessTools.UNIX_SHELL, shellCommand.get(0).equals(ExternalProcessTools.UNIX_SHELL));
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell options must be "
                    + ExternalProcessTools.UNIX_SHELL_OPTIONS, shellCommand.get(1).equals(ExternalProcessTools.UNIX_SHELL_OPTIONS));
        }
        assertEquals("The external command " + externalCommand + " must be keeped unchanged.", externalCommand, shellCommand.get(2));

        log.trace("<buildShellCommand()");
    }

    @Test
    public void writeTemporaryCrtFileToDisk() throws Exception {
        log.trace(">writeTemporaryCrtFileToDisk()");
        final String filePrefix = ExternalProcessTools.class.getName();
        final String fileExtension = ".crt";
        final byte[] bytes = createSelfSignedX509TestCertificate("Foo Bar Ltd.").getEncoded();
        File file = null;
        try {
            file = ExternalProcessTools.writeTemporaryFileToDisk(filePrefix, fileExtension, bytes);
            assertNotNull("Null should never be returned from this method.", file);
            assertTrue("The file was not written to disk correctly.", file.exists());
            assertTrue("The file was written, but it's not readable.", file.canRead());
            assertTrue("The file was not given the file prefix specified as argument.", file.getName().startsWith(filePrefix));
            assertTrue("The file was not given the file extension given as argument.", file.getName().endsWith(fileExtension));
            assertArrayEquals("The file data read from disk does not match the data written.", bytes,
                    FileTools.readFiletoBuffer(file.getCanonicalPath()));
        } finally {
            // Delete file
            if (file.exists() && !file.delete()) {
                file.deleteOnExit();
            }
            log.trace("<writeTemporaryCrtFileToDisk()");
        }
    }

    @Test
    public void writeTemporaryTmpFileToDisk() throws Exception {
        log.trace(">writeTemporaryCrtFileToDisk()");
        final String filePrefix = ExternalProcessTools.class.getName();
        final String fileExtension = null;
        final byte[] bytes = "Foobar".getBytes();
        File file = null;
        try {
            file = ExternalProcessTools.writeTemporaryFileToDisk(filePrefix, fileExtension, bytes);
            assertNotNull("Null should never be returned from this method.", file);
            assertTrue("The file was not written to disk correctly.", file.exists());
            assertTrue("The file was written, but it's not readable.", file.canRead());
            assertTrue("The file was not given the file prefix specified as argument.", file.getName().startsWith(filePrefix));
            assertTrue("The file was not given the default file extension (.tmp) when null was given as argument.", file.getName().endsWith(".tmp"));
            assertArrayEquals("The file data read from disk does not match the data written.", bytes,
                    FileTools.readFiletoBuffer(file.getCanonicalPath()));
        } finally {
            // Delete file
            if (file.exists() && !file.delete()) {
                file.deleteOnExit();
            }
            log.trace("<writeTemporaryCrtFileToDisk()");
        }
    }

    /**
     * Launches an external command. Arguments does not contain place holder {@link ExternalProcessTools#PLACE_HOLDER_CERTIFICATE}
     * -> certificate is written as DER to disk and the full path of temporary file is inserted as first parameter.
     * See script: resources/(platform)/external_process_tools_with_write_to_disk_exit_code_0.(platform-suffix).
     *
     * @throws Exception any exception.
     */
    @Test
    public void launchExternalCommandWithWriteFileToDisk() throws Exception {
        log.trace(">launchExternalCommandWithWriteFileToDisk()");
        
        // Platforms: MS Windows and Unix/Linux.
        final X509Certificate certificate = createSelfSignedX509TestCertificate("test03Launch");
        final String cmd = getFilePathFromClasspath("external_process_tools_with_write_to_disk_exit_code_0");
        List<String> out = null;
        final List<String> arguments = new ArrayList<String>();
        int cnt = -1;
        
        // A:1 Script contains output to ERROUT but should not fail because of failOnStandardError=false. ERROUT should have been logged.
        try {
            arguments.clear();
            out = ExternalProcessTools.launchExternalCommand(cmd, certificate.getEncoded(), true, false, true, true, arguments,
                    this.getClass().getName());
            if (log.isDebugEnabled()) {
                log.debug("Out A:1: " + out);
            }
            assertTrue("The exit code must be 0.", new Integer(0).equals(ExternalProcessTools.extractExitCode(out)));
            cnt = count(out, ExternalProcessTools.STDOUT_PREFIX);
            assertTrue( cnt + " line(s) must have been logged to STDOUT.", cnt == 3);
            cnt = count(out, ExternalProcessTools.ERROUT_PREFIX);
            // Re-factoring required: cnt should be 1 here, but error logging is lost if failOnStandartError=false!
            assertTrue(cnt + " line(s) must have been logged to ERROUT.", cnt == 0);
        } catch(Exception e) {
            log.warn(e.getMessage(), e);
            fail("The external command '" + cmd + "' should have succeeded (failOnStandardError=false): " + e.getMessage());
        }
        
        // A:2 Same thing but switch off logging.
        try {
            arguments.clear();
            out = ExternalProcessTools.launchExternalCommand(cmd, certificate.getEncoded(), true, false, false, false, arguments,
                    this.getClass().getName());
            if (log.isDebugEnabled()) {
                log.debug("Out A:2: " + out);
            }
            assertTrue("The exit code must be 0.", new Integer(0).equals(ExternalProcessTools.extractExitCode(out)));
            cnt = count(out, ExternalProcessTools.STDOUT_PREFIX);
            assertTrue(cnt + " line(s) must have been logged to STDOUT.", cnt == 0);
            cnt = count(out, ExternalProcessTools.ERROUT_PREFIX);
            assertTrue(cnt + " line(s) must have been logged to ERROUT.", cnt == 0);
        } catch(Exception e) {
            log.warn(e.getMessage(), e);
            fail("The external command '" + cmd + "' should have succeeded (failOnStandardError=false): " + e.getMessage());
        }
        
        // A:3 Turn on logging again but let the call fail (failOnStandardError=true).
        try {
            arguments.clear();
            out = ExternalProcessTools.launchExternalCommand(cmd, certificate.getEncoded(), true, true, true, true, arguments,
                    this.getClass().getName());
            fail("The external command '" + cmd + "' should have failed (failOnStandardError=true).");
        } catch(Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Out A:3: " + out, e);
            }
            assertTrue("The exit code must be 0.", new Integer(0).equals(ExternalProcessTools.extractExitCode(out)));
            cnt = count(out, ExternalProcessTools.STDOUT_PREFIX);
            // Re-factoring required: cnt should be 1 here, but STDOUT logging is lost.
            assertTrue(cnt + " line(s) must have been logged to STDOUT.", cnt == 0);
            cnt = count(out, ExternalProcessTools.ERROUT_PREFIX);
            // Re-factoring required: cnt should be 1 here, but ERROUT logging is lost.
            assertTrue(cnt + " line(s) must have been logged to ERROUT.", cnt == 0);
        }
        
        // A:4 Turn off logging again but let call fail (failOnStandardError=false).
        try {
            arguments.clear();
            out = ExternalProcessTools.launchExternalCommand(cmd, certificate.getEncoded(), true, true, false, false, arguments,
                    this.getClass().getName());
            fail("The external command '" + cmd + "' should have failed (failOnStandardError=true).");
        } catch(Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Out A:4: " + out, e);
            }
            assertTrue("The exit code must be 0.", new Integer(0).equals(ExternalProcessTools.extractExitCode(out)));
            cnt = count(out, ExternalProcessTools.STDOUT_PREFIX);
            assertTrue(cnt + " line(s) must have been logged to STDOUT.", cnt == 0);
            cnt = count(out, ExternalProcessTools.ERROUT_PREFIX);
            assertTrue(cnt + " line(s) must have been logged to ERROUT.", cnt == 0);
        }
        
        log.trace("<launchExternalCommandWithWriteFileToDisk()");
    }
    
    /**
     * Launches an external command. Arguments contains place holder {@link ExternalProcessTools#PLACE_HOLDER_CERTIFICATE} 
     * -> certificate is written to STDIN as PEM string.
     * 
     * @throws Exception any exception.
     */
    @Test
    public void launchExternalCommandDontWriteFileToDisk() throws Exception {
        log.trace(">launchExternalCommandDontWriteFileToDisk()");
        
        // Platforms: Unix/Linux only.
        // B: Script parameters contains '%cert%' -> PEM certificate is in STDIN.
        if (!SystemUtils.IS_OS_WINDOWS) {            
            final X509Certificate certificate = createSelfSignedX509TestCertificate("launchExternalCommandDontWriteFileToDisk");
            final String cmd = getFilePathFromClasspath("external_process_tools_dont_write_to_disk");
            List<String> out = null;
            final List<String> arguments = new ArrayList<String>();
            int cnt = -1;
            int exitCode = 0;
            
            // B:1 Script contains output to ERROUT but should not fail because of failOnStandardError=false.
            try {
                arguments.clear();
                arguments.add("param1");
                arguments.add(Integer.toString(exitCode));
                arguments.add(ExternalProcessTools.PLACE_HOLDER_CERTIFICATE);
                out = ExternalProcessTools.launchExternalCommand(cmd, certificate.getEncoded(), true, false, true, true, arguments,
                        this.getClass().getName());
                assertTrue("The exit code must be " + exitCode + ".", new Integer(0).equals(ExternalProcessTools.extractExitCode(out)));
                cnt = count(out, ExternalProcessTools.STDOUT_PREFIX);
                assertTrue("At least " + cnt + " line(s) must have been logged to STDOUT.", cnt > 3);
                cnt = count(out, ExternalProcessTools.ERROUT_PREFIX);
                // Re-factoring required: cnt should be 1 here, but ERROUT logging is lost.
                assertTrue(cnt + " line(s) must have been logged to ERROUT.", cnt == 0);
            } catch(Exception e) {
                log.warn(e.getMessage(), e);
                fail("The external command '" + cmd + "' should have succeeded (failOnStandardError=false): " + e.getMessage());
            }
        }
        
        log.trace("<launchExternalCommandDontWriteFileToDisk()");
    }
    
    private final X509Certificate createSelfSignedX509TestCertificate(final String cn) throws Exception {
        final KeyPair keyPair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);
        return CertTools.genSelfCert(
                "C=Test,O=Test,OU=Test,CN="+cn, 365, null, 
                keyPair.getPrivate(), keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA256_WITH_RSA, true);
    }
    
    /**
     * Gets the platform dependent full path of the file in the class path.
     * 
     * @param classpath the class path (or filename -> put inside resources directory).
     * @return the full path.
     */
    private final String getFilePathFromClasspath(final String classpath) {
        final String fileSuffix = SystemUtils.IS_OS_WINDOWS ? ".bat" : ".sh";
        final String subFolder = SystemUtils.IS_OS_WINDOWS ? "windows" : "unix";
        final String path = "resources/platform/" + subFolder + "/" + classpath + fileSuffix;
        final String result = ExternalProcessToolsTest.class.getClassLoader().getResource(path).getPath();
        if (log.isDebugEnabled()) {
            log.debug("Get file path by class path: " + classpath + " - " + result);
        }
        return SystemUtils.IS_OS_WINDOWS ? result.replaceFirst("/", StringUtils.EMPTY) : result;
    }
    
    /** Counts the occurrence of string prefix in the list. */
    private final int count(final List<String> list, final String prefix) {
        int result = 0;
        if (CollectionUtils.isNotEmpty(list)) {
            result = CollectionUtils.countMatches(list, new Predicate() {
                @Override
                public boolean evaluate(Object string) {
                    return ((String) string).startsWith(prefix);
                }
            });
        }
        return result;
    }
}
