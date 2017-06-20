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
import java.io.FileReader;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.validation.CouldNotRemovePublicKeyBlacklistException;
import org.cesecore.keys.validation.KeyGeneratorSources;
import org.cesecore.keys.validation.PublicKeyBlacklist;
import org.cesecore.keys.validation.PublicKeyBlacklistDoesntExistsException;
import org.cesecore.keys.validation.PublicKeyBlacklistExistsException;
import org.cesecore.keys.validation.PublicKeyBlacklistKeyValidator;
import org.cesecore.keys.validation.PublicKeyBlacklistSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports certificate files to the database for a given CA
 *
 * @version $Id: CaImportPublicKeyBlacklistCommand.java 24940 2017-04-01 09:43:55Z anjakobs $
 */
public class UpdatePublicKeyBlacklistCommand extends BaseCaAdminCommand {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(UpdatePublicKeyBlacklistCommand.class);

    public static final String COMMAND_KEY = "--command";
    public static final String KEY_SPECIFICATIONS_KEY = "--keyspecs";
    public static final String KEY_GENERATION_SOURCES_KEY = "--sources";
    public static final String DIRECTORY_KEY = "--dir";
    public static final String UPDATE_MODE_KEY = "--mode";
    public static final String RESUME_ON_ERROR_KEY = "--resumeonerror";

    public static final String COMMAND_ADD = "add";
    public static final String COMMAND_REMOVE = "remove";
    public static final String UPDATE_MODE_FINGERPINT = "fingerprint";
    public static final String CSV_SEPARATOR = ",";

    {
        registerParameter(new Parameter(COMMAND_KEY, "Command to execute", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Command to execute. Use " + COMMAND_ADD + " or " + COMMAND_REMOVE + "."));
        registerParameter(new Parameter(UPDATE_MODE_KEY, "Update mode", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Set to fingerprint if the files in --dir shall be treated as CSV files, containing on public key fingerprint per line with "
                        + PublicKeyBlacklistKeyValidator.DIGEST_ALGORITHM
                        + " hash and optional additional information (key specification or key generation sources separated by comma: I.e.: fingerprint,keyspec,keygensource"));
        registerParameter(new Parameter(KEY_SPECIFICATIONS_KEY, "Key specifications", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Comma separated list of key specifications. Use <Algorithm><Length>, i.e RSA2048,ECDSA256 or all if missing. If --mode fingerprint is chosen, the first value is set as default value when running with --command add. If running with --command remove, only blacklist entries with that key specification are removed."));
        registerParameter(new Parameter(KEY_GENERATION_SOURCES_KEY, "Key generation sources", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Comma separated list of key generator sources. Use " + KeyGeneratorSources.toStringList()
                        + " or all if missing.  If --mode fingerprint is chosen, the first value is set as default value when running with --command add. If running with --command remove, only blacklist entries with that key generation source are removed."));
        registerParameter(new Parameter(DIRECTORY_KEY, "Public key directory", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Directory with public key files or CSV files containing public key fingerprints and additional information."));
        registerParameter(Parameter.createFlag(RESUME_ON_ERROR_KEY,
                "Set if the command should resume in case of errors, or stop on first one. Default is stop."));
    }

    private static final int STATUS_OK = 0;
    private static final int STATUS_READ_ERROR = 1;
    private static final int STATUS_REDUNDANT = 2;
    private static final int STATUS_CONSTRAINTVIOLATION = 3;
    private static final int STATUS_GENERALIMPORTERROR = 4;

    @Override
    public String getMainCommand() {
        return "updatepublickeyblacklist";
    }

    @SuppressWarnings("unchecked")
    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");

        CryptoProviderTools.installBCProviderIfNotAvailable();

        try {
            final String command = parameters.get(COMMAND_KEY);
            final String keySpecificationsString = parameters.get(KEY_SPECIFICATIONS_KEY);
            final String keyGeneratorSourcesString = parameters.get(KEY_GENERATION_SOURCES_KEY);
            final String importDirString = parameters.get(DIRECTORY_KEY);
            final boolean byFingerprint = UPDATE_MODE_FINGERPINT.equals(parameters.get(UPDATE_MODE_KEY));
            final boolean resumeOnError = parameters.containsKey(RESUME_ON_ERROR_KEY);

            List<String> keySpecifications = new ArrayList<String>(); // Allows any
            if (StringUtils.isNotBlank(keySpecificationsString)) {
                keySpecifications = Arrays.asList(keySpecificationsString.split(CSV_SEPARATOR));
            }
            List<Integer> sources = new ArrayList<Integer>(); // Allows any
            if (StringUtils.isNotBlank(keyGeneratorSourcesString)) {
                sources = new ArrayList<Integer>(CollectionUtils.intersection(KeyGeneratorSources.sources(),
                        StringTools.idStringToListOfInteger(keyGeneratorSourcesString, CSV_SEPARATOR)));
            }

            // Get all files in the directory to add/remove to/from public key blacklist. 
            final File importDir = new File(importDirString);
            if (!importDir.isDirectory()) {
                log.error("'" + importDirString + "' is not a directory.");
                return CommandResult.CLI_FAILURE;
            }
            final File files[] = importDir.listFiles();
            if (files == null || files.length < 1) {
                log.error("No files in directory '" + importDir.getCanonicalPath() + "'. Nothing to do.");
                return CommandResult.CLI_FAILURE;
            }

            // Read public key file (or lists of fingerprint) to add/remove to/from public key blacklist.
            int redundant = 0;
            int readError = 0;
            int constraintViolation = 0;
            int generalImportError = 0;
            int importOk = 0;
            int state;
            String path;
            FileReader reader;
            List<String> lines;
            PublicKey publicKey;
            String fingerprint;
            String keySpecification;
            Integer keyGenerationSource;
            byte[] asn1Encodedbytes;

            for (final File file : files) {
                state = STATUS_GENERALIMPORTERROR;
                try {
                    keySpecification = null;
                    path = file.getAbsolutePath();
                    log.debug("Read file " + path);

                    if (COMMAND_ADD.equals(command)) {
                        if (!byFingerprint) {
                            log.info("Read public key file " + path);
                            asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(path));
                            if (null == (publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes))) {
                                state = STATUS_READ_ERROR;
                            } else {
                                state = addPublicKeyToBlacklist(publicKey);
                            }
                        } else {
                            log.info("Read public key fingerprints file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            String[] tokens;
                            for (String line : lines) {
                                tokens = line.split(CSV_SEPARATOR);
                                if (tokens.length > 0) {
                                    fingerprint = tokens[0];
                                    keySpecification = null;
                                    if (CollectionUtils.isNotEmpty(keySpecifications)) {
                                        keySpecification = keySpecifications.get(0);
                                    }
                                    if (tokens.length > 1) {
                                        keySpecification = tokens[1];
                                    }
                                    keyGenerationSource = null;
                                    if (CollectionUtils.isNotEmpty(sources)) {
                                        keyGenerationSource = sources.get(0);
                                    }
                                    if (tokens.length > 2) {
                                        keyGenerationSource = KeyGeneratorSources.valueOf(tokens[2]).getSource();
                                    }
                                    addPublicKeyFingerprintToBlacklist(fingerprint, keySpecification, keyGenerationSource);
                                }
                            }
                        }
                    } else if (COMMAND_REMOVE.equals(command)) {
                        if (!byFingerprint) {
                            log.info("Remove public key by file " + path);
                            asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(path));
                            if (null == (publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes))) {
                                state = STATUS_READ_ERROR;
                            } else {
                                state = removePublicKeyToBlacklist(publicKey);
                            }
                        } else {
                            log.info("Remove public keys by fingerprints listed in file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            String[] tokens;
                            for (String line : lines) {
                                tokens = line.split(CSV_SEPARATOR);
                                if (tokens.length > 0) {
                                    fingerprint = tokens[0];
                                    removeFromBlacklist(fingerprint);
                                }
                            }
                        }
                    }

                    switch (state) {
                    case STATUS_OK:
                        importOk++;
                        break;
                    case STATUS_READ_ERROR:
                        readError++;
                        break;
                    case STATUS_REDUNDANT:
                        redundant++;
                        break;
                    case STATUS_CONSTRAINTVIOLATION:
                        constraintViolation++;
                        break;
                    case STATUS_GENERALIMPORTERROR:
                        generalImportError++;
                        break;
                    default:
                        generalImportError++;
                        break;
                    }
                    if (!resumeOnError && STATUS_OK != state) {
                        throw new Exception("Update public key blacklist aborted --resumeonerror=" + resumeOnError);
                    }
                } catch (Exception e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Update public key blacklist failed: " + e.getMessage(), e);
                    }
                    if (!resumeOnError) {
                        throw new Exception("Update public key blacklist aborted --resumeonerror=" + resumeOnError);
                    }
                }
            }

            printSummary(importOk, readError, redundant, constraintViolation, generalImportError);
        } catch (Exception e) {
            log.error("Import public key blacklist aborted: " + e.getMessage(), e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        log.trace("<execute()");
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Updates the public key blacklist data store.";
    }

    @Override
    public String getFullHelpText() {
        final StringBuilder result = new StringBuilder();
        result.append("\n\n" + getCommandDescription() + "\n\n");
        result.append(
                "Every file in the target directory is parsed and must contain one PEM formatted RSA or ECC public key.\n\nIf --mode fingerpint is chosen only the public key fingerprints with "
                        + PublicKeyBlacklistKeyValidator.DIGEST_ALGORITHM
                        + " hash are used to add or remove blacklist entries, and every file is treated as CSV file with one public key fingerprint per line."
                        + "\n\n");
        return result.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    /**
     * Adds a public key to the public key blacklist.
     * 
     * @param publicKey the public key to add.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    public int addPublicKeyToBlacklist(final PublicKey publicKey) throws Exception {
        log.trace(">addPublicKeyToBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final String fingerprint = CertTools.createPublicKeyFingerprint(publicKey, PublicKeyBlacklistKeyValidator.DIGEST_ALGORITHM);
        final PublicKeyBlacklist entry = new PublicKeyBlacklist();
        entry.setFingerprint(fingerprint);
        entry.setPublicKey(publicKey);
        entry.setKeyspec(AlgorithmTools.getKeySpecification(publicKey));
        entry.setPublicKeyString(publicKey.toString());
        log.info("Try to add public key into public key blacklist (fingerprint=" + fingerprint + ").");
        result = addToBlacklist(entry);
        log.trace("<addPublicKeyToBlacklist()");
        return result;
    }

    /**
     * Removes a public key from the public key blacklist.
     * 
     * @param publicKey the public key to remove.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    public int removePublicKeyToBlacklist(final PublicKey publicKey) throws Exception {
        log.trace(">removePublicKeyFromBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final String fingerprint = CertTools.createPublicKeyFingerprint(publicKey, PublicKeyBlacklistKeyValidator.DIGEST_ALGORITHM);
        log.info("Try to remove public key from public key blacklist (fingerprint=" + fingerprint + ").");
        result = removeFromBlacklist(fingerprint);
        log.trace("<removePublicKeyFromBlacklist()");
        return result;
    }

    /**
     * Adds a fingerprint to the public key blacklist.
     * 
     * @param fingerprint the fingerprint to add.
     * @param keySpecification the key specification.
     * @param keyGeneratorSource the key generation source (see {@link KeyGeneratorSources#getSource()})
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    public int addPublicKeyFingerprintToBlacklist(final String fingerprint, final String keySpecification, final Integer keyGeneratorSource) throws Exception {
        log.trace(">addPublicKeyFingerprintToBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final PublicKeyBlacklist entry = new PublicKeyBlacklist();
        entry.setFingerprint(fingerprint);
        entry.setPublicKey(null);
        entry.setKeyspec(keySpecification);
        entry.setSource(keyGeneratorSource);
        entry.setPublicKeyString(null);
        log.info("Try to add public key into public key blacklist by fingerprint (fingerprint=" + fingerprint + ").");
        result = addToBlacklist(entry);
        log.trace("<addPublicKeyFingerprintToBlacklist()");
        return result;
    }

    /**
     * Adds a public key to the public key blacklist if a public key with that fingerprint does not exists already.
     * 
     * @param entry the public key blacklist entry.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    private int addToBlacklist(final PublicKeyBlacklist entry) throws Exception {
        log.trace(">addToBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final PublicKeyBlacklistSessionRemote blacklistSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublicKeyBlacklistSessionRemote.class);
        try {
            blacklistSession.addPublicKeyBlacklist(getAuthenticationToken(), entry);
            result = STATUS_OK;
        } catch (PublicKeyBlacklistExistsException e) {
            result = STATUS_CONSTRAINTVIOLATION;
            log.info("Public key blacklist entry with public key fingerprint " + entry.getFingerprint() + " already exists.");
            throw e;
        } catch (AuthorizationDeniedException e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Authorization denied to add public key to blacklist.");
            throw e;
        } catch (Exception e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Error while adding public key to blacklist: " + e.getMessage());
            throw e;
        }
        log.trace("<addToBlacklist()");
        return result;
    }

    /**
     * Removes a public key from the public key blacklist.
     * 
     * @param entry the public key fingerprint.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    private int removeFromBlacklist(final String fingerprint) throws Exception {
        log.trace(">removeFromBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final PublicKeyBlacklistSessionRemote blacklistSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublicKeyBlacklistSessionRemote.class);
        try {
            blacklistSession.removePublicKeyBlacklist(getAuthenticationToken(), fingerprint);
            result = STATUS_OK;
        } catch (PublicKeyBlacklistDoesntExistsException e) {
            result = STATUS_CONSTRAINTVIOLATION;
            log.info("Public key blacklist entry with public key fingerprint " + fingerprint + " does not exist.");
            throw e;
        } catch (CouldNotRemovePublicKeyBlacklistException e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Authorization denied to remove public key from blacklist.");
            throw e;
        } catch (Exception e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Error while removing public key from blacklist: " + e.getMessage());
            throw e;
        }
        log.trace("<removeFromBlacklist()");
        return result;
    }

    /**
     * Logs the summary to STDOUT.
     * 
     * @param importOk OK counter
     * @param readError read error counter
     * @param redundant redundant counter
     * @param constraintViolation constraint violation counter
     * @param generalImportError general import error counter
     */
    private final void printSummary(final int importOk, final int readError, final int redundant, final int constraintViolation,
            final int generalImportError) {
        // Print resulting statistics
        log.info("\nImport summary:");
        log.info(importOk + " public key blacklist entries were imported with success (STATUS_OK)");
        if (readError > 0) {
            log.info(readError + " public key blacklist entries could not be parsed (STATUS_READERROR)");
        }
        if (redundant > 0) {
            log.info(redundant + " public key blacklist entries were already present in the database (STATUS_REDUNDANT)");
        }
        if (constraintViolation > 0) {
            log.info(constraintViolation + " public key blacklist entries could not be stored (STATUS_CONSTRAINTVIOLATION)");
        }
        if (generalImportError > 0) {
            log.info(generalImportError + " public key blacklist entries were not imported due to other errors (STATUS_GENERALIMPORTERROR)");
        }
    }
}
