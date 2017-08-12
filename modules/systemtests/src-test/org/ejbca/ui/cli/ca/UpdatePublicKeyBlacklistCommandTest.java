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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.validation.PublicKeyBlacklistDoesntExistsException;
import org.ejbca.core.ejb.ca.validation.PublicKeyBlacklistSessionRemote;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class UpdatePublicKeyBlacklistCommandTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(UpdatePublicKeyBlacklistCommandTest.class);

    // Directory and file constants (see ${project.dir}/resources)
    private static final String TEST_RESOURCE_EMPTY_FOLDER = "resources/empty";
    private static final String TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS = "resources/publickey/rsa2048.pub.pem";
    private static final String TEST_RESOURCE_ADD_REMOVE_FINGERPINTS = "resources/publickeyfingerprint/public_key_fingerprints_add_remove_test.txt";

    /** Always allow authentication token. */
    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            UpdatePublicKeyBlacklistCommandTest.class.getSimpleName());

    /** Public key blacklist remote session. */
    private static final PublicKeyBlacklistSessionRemote publicKeyBlacklistSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(PublicKeyBlacklistSessionRemote.class);

    /** Command to be tested. */
    private final UpdatePublicKeyBlacklistCommand command = new UpdatePublicKeyBlacklistCommand();

    @BeforeClass
    public static void beforeClass() throws Exception {
        log.trace(">beforeClass()");

        CryptoProviderTools.installBCProvider();
        // Remove test entries from blacklist.
        removePublicKeyFingerprintsFromBlacklist(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        removePublicKeysFromBlacklist(TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);

        log.trace("<beforeClass()");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        log.trace(">afterClass()");

        // Remove test entries from blacklist.
        removePublicKeyFingerprintsFromBlacklist(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        removePublicKeysFromBlacklist(TEST_RESOURCE_ADD_REMOVE_PUBLIC_KEYS);

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
        Map<String, String> keySpecifications = new HashMap<String, String>();
        PublicKey publicKey;
        PublicKeyBlacklistEntry entry;
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
                entry = publicKeyBlacklistSession.getPublicKeyBlacklistEntry(fingerprint);
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
                entry = publicKeyBlacklistSession.getPublicKeyBlacklistEntry(fingerprint);
                assertTrue("Public key blacklist entries must have been removed.", null == entry);
            } catch (CertificateParsingException e) {
                // NOOP -> Only if it was possible to parse it.
            }
        }

        // Other error cases.
        // B-1: Try add command with an empty folder.
        url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_EMPTY_FOLDER);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_EMPTY_FOLDER);
        }
        dir = new File(url.getPath());
        log.info("Using directory (empty folder): " + dir.getAbsolutePath());
        final int countEntries = publicKeyBlacklistSession.getPublicKeyBlacklistEntryIdToFingerprintMap().size();
        args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Add empty dir for lists of public key must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that nothing was imported ~
        Assert.assertTrue("After importing an empty folder, the number of blacklist entries must still be the same.",
                publicKeyBlacklistSession.getPublicKeyBlacklistEntryIdToFingerprintMap().size() == countEntries);

        log.trace("<test01AddAndRemoveCommand()");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void test02AddAndRemoveCommandModeByFingerprint() throws CertificateException, IOException {
        log.trace(">test02AddAndRemoveCommandModeByFingerprint()");

        URL url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_ADD_REMOVE_FINGERPINTS);
        }
        File dir = new File(url.getPath()).getParentFile();
        log.info("Using directory (fingerprints): " + dir.getAbsolutePath());

        // A-1: Insert public key blacklist entries that does not exist, including invalid files (wrong format, unknown key).
        String[] args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        CommandResult result = command.execute(args);
        Assert.assertTrue("Add lists of fingerprints which do not exists must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that public key fingerprints were imported.
        File[] files = dir.listFiles();
        PublicKeyBlacklistEntry entry;
        String fingerprint;
        FileReader reader;
        List<String> lines;
        List<String> fingerprints = new ArrayList<String>();
        for (File file : files) {
            reader = new FileReader(file);
            lines = IOUtils.readLines(reader);
            IOUtils.closeQuietly(reader);
            String[] tokens;
            for (String line : lines) {
                tokens = line.split(UpdatePublicKeyBlacklistCommand.CSV_SEPARATOR);
                if (tokens.length > 0) {
                    fingerprint = tokens[0];
                    fingerprints.add(fingerprint);
                    if (log.isDebugEnabled()) {
                        log.debug("Trying to retrieve public key blacklist entry: "+fingerprint);
                    }
                    entry = publicKeyBlacklistSession.getPublicKeyBlacklistEntry(fingerprint);
                    assertTrue("Public key fingerprint must have been imported.", null != entry);
                }
            }
        }

        // A-2: Remove again.
        args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_REMOVE,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Remove lists of fingerprints which do exist must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        for (String string : fingerprints) {
            entry = publicKeyBlacklistSession.getPublicKeyBlacklistEntry(string);
            assertTrue("Public key must exists in data store anymore.", null == entry);
        }

        // Other error cases.
        // B-1: Try add command with an empty folder.
        final int countEntries = publicKeyBlacklistSession.getPublicKeyBlacklistEntryIdToFingerprintMap().size();
        url = UpdatePublicKeyBlacklistCommandTest.class.getClassLoader().getResource(TEST_RESOURCE_EMPTY_FOLDER);
        if (null == url) {
            throw new IllegalArgumentException("Could not find resource " + TEST_RESOURCE_EMPTY_FOLDER);
        }
        dir = new File(url.getPath());
        log.info("Using directory (empty folder): " + dir.getAbsolutePath());
        args = new String[] { UpdatePublicKeyBlacklistCommand.COMMAND_KEY, UpdatePublicKeyBlacklistCommand.COMMAND_ADD,
                UpdatePublicKeyBlacklistCommand.UPDATE_MODE_KEY, UpdatePublicKeyBlacklistCommand.UPDATE_MODE_FINGERPINT,
                UpdatePublicKeyBlacklistCommand.DIRECTORY_KEY, dir.getAbsolutePath(), UpdatePublicKeyBlacklistCommand.RESUME_ON_ERROR_KEY };
        result = command.execute(args);
        Assert.assertTrue("Add empty dir for lists of fingerprints must exit with success: " + result,
                result.getReturnCode() == CommandResult.SUCCESS.getReturnCode());
        // Verify that nothing was imported ~
        Assert.assertEquals("After importing an empty folder, the number of blacklist entries must still be the same.",
                countEntries, publicKeyBlacklistSession.getPublicKeyBlacklistEntryIdToFingerprintMap().size());

        log.trace("<test02AddAndRemoveCommandModeByFingerprint()");
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
                publicKeyBlacklistSession.removePublicKeyBlacklistEntry(authenticationToken, fingerprint);
            } catch (PublicKeyBlacklistDoesntExistsException e) {
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
    @SuppressWarnings("unchecked")
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
                        publicKeyBlacklistSession.removePublicKeyBlacklistEntry(authenticationToken, fingerprint);
                    } catch (PublicKeyBlacklistDoesntExistsException e) {
                        // NOOP
                    } catch (Exception e) {
                        fail("Could not delete public key blacklist entries.");
                    }
                }
            }
        }
    }
}
