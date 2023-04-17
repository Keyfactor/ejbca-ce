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
package org.ejbca.ui.cli.ca;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.validation.BlacklistDoesntExistsException;
import org.ejbca.core.ejb.ca.validation.BlacklistSessionRemote;
import org.ejbca.core.model.validation.BlacklistEntry;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * <p>Run these tests with:
 * 
 * <pre>ant test:runone -Dtest.runone=UpdatePublicKeyBlacklistCommandTest</pre>.
 * 
 * @version $Id$
 */
public class UpdatePublicKeyBlacklistCommandTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(UpdatePublicKeyBlacklistCommandTest.class);

    // Directory and file constants (see ${project.dir}/resources)
    private static File emptyFolder;
    private static final String TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS = "resources/publickey/rsa2048.pub.pem";
    private static final String TEST_RESOURCE_ADD_REMOVE_FINGERPINTS = "resources/publickeyfingerprint/csv/fingerprints.txt";
    private static final String TEST_RESOURCE_ADD_REMOVE_DEBIAN_FINGERPINTS = "resources/publickeyfingerprint/debian/fingerprints.txt";

    /** Always allow authentication token. */
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            UpdatePublicKeyBlacklistCommandTest.class.getSimpleName());

    /** Public key blacklist remote session. */
    private static final BlacklistSessionRemote blacklistSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(BlacklistSessionRemote.class);

    /** Command to be tested. */
    private final UpdatePublicKeyBlacklistCommand command = new UpdatePublicKeyBlacklistCommand();

    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass()");

        CryptoProviderTools.installBCProvider();
        // Remove test entries from blacklist.
        removePublicKeyFingerprintsFromBlacklist(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        removePublicKeysFromBlacklist(TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);
        
        emptyFolder = FileTools.createTempDirectory();
        emptyFolder.deleteOnExit();

        log.trace("<beforeClass()");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        log.trace(">afterClass()");

        // Remove test entries from blacklist.
        removePublicKeyFingerprintsFromBlacklist(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        removePublicKeysFromBlacklist(TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);
        if (emptyFolder.exists()) {
            emptyFolder.delete();
        }

        log.trace("<afterClass()");
    }

    @Test
    public void test01AddAndRemoveCommand() throws Exception {
        log.trace(">test01AddAndRemoveCommand()");

        URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);
        }
        File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory (public keys): " + dir.getAbsolutePath());

        // A-1: Add/remove public key blacklist entries that does not exist, including invalid files (wrong format, unknown key).
        String[] args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        CommandResult result = command.execute(args);
        Assert.assertTrue("Add public keys of a folder with not importable file and resumeonerror=true must exit with success code: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that public key blacklist entries were imported.
        File[] files = dir.listFiles();
        Map<String, String> keySpecifications = new HashMap<>();
        PublicKey publicKey;
        BlacklistEntry entry;
        byte[] asn1Encodedbytes;
        String fingerprint;
        for (File file : files) {
            try {
                asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(file.getAbsolutePath()));
                publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes);
                fingerprint = PublicKeyBlacklistEntry.createFingerprint(publicKey);
                keySpecifications.put(fingerprint, AlgorithmTools.getKeySpecification(publicKey));
                if (log.isDebugEnabled()) {
                    log.debug("Validate public key blacklist entry exists in data store: " + fingerprint);
                }
                entry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, fingerprint);
            } catch (CertificateParsingException e) {
                // NOOP -> Only if it was possible to parse it.
            }
        }

        // A-2: Remove again.
        args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_REMOVE,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Remove public keys of a folder with not importable file and resumeonerror=true must cause a CLI failure: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());

        for (File file : files) {
            try {
                asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(file.getAbsolutePath()));
                publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes);
                fingerprint = PublicKeyBlacklistEntry.createFingerprint(publicKey);
                keySpecifications.put(fingerprint, AlgorithmTools.getKeySpecification(publicKey));
                if (log.isDebugEnabled()) {
                    log.debug("Validate public key blacklist entry exists in data store: " + fingerprint);
                }
                entry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, fingerprint);
                assertTrue("Public key blacklist entries must have been removed.", null == entry);
            } catch (CertificateParsingException e) {
                // NOOP -> Only if it was possible to parse it.
            }
        }

        // Other error cases.
        // B-1: Try add command with an empty folder.
        log.info("Using directory (empty folder): " + emptyFolder.getAbsolutePath());
        final int countEntries = blacklistSession.getBlacklistEntryIdToValueMap().size();
        args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, emptyFolder.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Add empty dir for lists of public key must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that nothing was imported ~
        Assert.assertTrue("After importing an empty folder, the number of blacklist entries must still be the same.",
                blacklistSession.getBlacklistEntryIdToValueMap().size() == countEntries);

        log.trace("<test01AddAndRemoveCommand()");
    }

    @Test
    public void test02AddAndRemoveCommandModeByFingerprint() throws IOException {
        log.trace(">test02AddAndRemoveCommandModeByFingerprint()");

        final URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        }
        final File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory with fingerprints in CSV file:" + dir.getAbsolutePath());

        // A-1: Insert public key blacklist entries from file
        String[] args = new String[] { 
                UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPRINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(),
                UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY
        };
        CommandResult result = command.execute(args);
        Assert.assertTrue("Adding 2 fingerprints should be successful. Command " + args.toString() + " did not exit with status " + CommandResult.SUCCESS + " but exited with " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        BlacklistEntry rsa1kEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "4961db269ce56da9447266f6f651369fa503ff4731a26923f762ec9e008005f2");
        assertTrue("Public key fingerprint '4961db269ce56da9447266f6f651369fa503ff4731a26923f762ec9e008005f2' is not blacklisted.", null != rsa1kEntry);
        BlacklistEntry rsa2kEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "93271e6b120f7e09487b8ec1bf0e16467a48a257d6d3e13ccd749e948d0cba0d");
        assertTrue("Public key fingerprint '93271e6b120f7e09487b8ec1bf0e16467a48a257d6d3e13ccd749e948d0cba0d' is not blacklisted.", null != rsa2kEntry);

        // A-2: Remove again.
        args = new String[] {
                UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_REMOVE,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPRINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(),
                UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY
        };
        result = command.execute(args);
        Assert.assertTrue("Removing 2 fingerprints should be successful. Command " + args.toString() + " did not exit with status " + CommandResult.SUCCESS + " but exited with " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        rsa1kEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "4961db269ce56da9447266f6f651369fa503ff4731a26923f762ec9e008005f2");
        assertTrue("Public key fingerprint '4961db269ce56da9447266f6f651369fa503ff4731a26923f762ec9e008005f2' should no longer be blacklisted.", null == rsa1kEntry);
        rsa2kEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "93271e6b120f7e09487b8ec1bf0e16467a48a257d6d3e13ccd749e948d0cba0d");
        assertTrue("Public key fingerprint '93271e6b120f7e09487b8ec1bf0e16467a48a257d6d3e13ccd749e948d0cba0d' should no longer be blacklisted.", null == rsa2kEntry);

        // Other error cases.
        // B-1: Try add command with an empty folder.
        final int countEntries = blacklistSession.getBlacklistEntryIdToValueMap().size();
        log.info("Using directory (empty folder): " + emptyFolder.getAbsolutePath());
        args = new String[] {
                UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPRINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, emptyFolder.getAbsolutePath(),
                UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY
        };
        result = command.execute(args);
        Assert.assertTrue("Add empty directory without a CSV file with fingerprints must exit with status " + CommandResult.SUCCESS + " but exited with " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that nothing was imported ~
        Assert.assertEquals("After importing an empty folder, the number of blacklist entries must still be the same.",
                countEntries, blacklistSession.getBlacklistEntryIdToValueMap().size());

        log.trace("<test02AddAndRemoveCommandModeByFingerprint()");
    }

    @Test
    public void test02AddAndRemoveCommandModeByDebianFingerprint() {
        log.trace(">test02AddAndRemoveCommandModeByDebianFingerprint()");

        final URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_ADD_REMOVE_DEBIAN_FINGERPINTS);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_ADD_REMOVE_DEBIAN_FINGERPINTS);
        }
        final File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory of Debian fingerprints: " + dir.getAbsolutePath());

        // Add
        String[] args = new String[] {
                UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_DEBIAN_FINGERPRINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), 
                UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        CommandResult result = command.execute(args);
        Assert.assertTrue("Add lists of fingerprints which do not not exist must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        final BlacklistEntry addedEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "0504bb261ca99c3d392e");
        assertTrue("Debian weak key 2048/i386/rnd/pid17691 should have been added to the blacklist.", null != addedEntry);

        // Remove
        args = new String[] { 
                UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_REMOVE,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_DEBIAN_FINGERPRINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), 
                UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Remove lists of Debian fingerprints which do exist must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        final BlacklistEntry removedEntry = blacklistSession.getBlacklistEntry(PublicKeyBlacklistEntry.TYPE, "0504bb261ca99c3d392e");
        assertTrue("Debian weak key 2048/i386/rnd/pid17691 should have been removed from the blacklist.", null == removedEntry);

        log.trace("<test02AddAndRemoveCommandModeByDebianFingerprint()");
    }

    /**
     * Removes all public keys found in all files in the same directory as resource.
     * 
     * @param resource the resource file to mark the target directory.
     * @throws IllegalArgumentException if the resource could not  be found.
     * @throws CertificateParsingException if a public key could not be parsed.
     * @throws IOException 
     */
    private static final void removePublicKeysFromBlacklist(String resource) throws CertificateParsingException, IOException {
        final URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(resource);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + resource);
        }
        final File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory (remove publicKey): " + dir.getAbsolutePath());
        final File[] files = dir.listFiles();
        PublicKey publicKey;
        byte[] asn1Encodedbytes;
        String fingerprint;
        for (File file : files) {
            log.info("Trying to remove public key blacklist entry: "+file.getCanonicalPath());
            asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(file.getAbsolutePath()));
            publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes);
            log.trace("Loaded public key " + publicKey);
            fingerprint = PublicKeyBlacklistEntry.createFingerprint(publicKey);
            try {
                blacklistSession.removeBlacklistEntry(authenticationToken, PublicKeyBlacklistEntry.TYPE, fingerprint);
            } catch (BlacklistDoesntExistsException e) {
                // NOOP
            } catch (Exception e) {
                fail("Could not delete public key blacklist entries.");
            }
        }
    }

    /**
     * Removes all public keys with the fingerprints found in all CSV files in the same directory as resource.
     * @param resource the resource file to mark the target directory.
     * @throws IllegalArgumentException if the resource could not  be found.s
     * @throws IOException any IO exception.
     * @throws FileNotFoundException if a file could not be found.
     */
    private static final void removePublicKeyFingerprintsFromBlacklist(final String resource)
            throws IllegalArgumentException, IOException, FileNotFoundException {
        final URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(resource);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + resource);
        }
        final File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory (remove fingerprint): " + dir.getAbsolutePath());
        final File[] files = dir.listFiles();
        FileReader reader;
        List<String> lines;
        String fingerprint;

        for (File file : files) {
            reader = new FileReader(file);
            lines = IOUtils.readLines(reader);
            IOUtils.closeQuietly(reader);
            String[] tokens;
            for (String line : lines) {
                tokens = line.split(UpdatePublicKeyBlacklistCommand.CSV_SEPARATOR);
                if (tokens.length > 0) {
                    fingerprint = tokens[0];
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Trying to remove public key blacklist entriy: "+fingerprint);
                        }
                        blacklistSession.removeBlacklistEntry(authenticationToken, PublicKeyBlacklistEntry.TYPE, fingerprint);
                    } catch (BlacklistDoesntExistsException e) {
                        // NOOP
                    } catch (Exception e) {
                        fail("Could not delete public key blacklist entries.");
                    }
                }
            }
        }
    }
}
