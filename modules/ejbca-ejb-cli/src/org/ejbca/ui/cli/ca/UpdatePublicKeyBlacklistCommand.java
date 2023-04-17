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
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.validation.BlacklistDoesntExistsException;
import org.ejbca.core.ejb.ca.validation.BlacklistExistsException;
import org.ejbca.core.ejb.ca.validation.BlacklistSessionRemote;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.keys.KeyTools;

/**
 * Imports certificate files to the database for a given CA
 *
 * @version $Id$
 */
public class UpdatePublicKeyBlacklistCommand extends BaseCaAdminCommand {
    private static final Logger log = Logger.getLogger(UpdatePublicKeyBlacklistCommand.class);

    public static final String COMMAND_KEY = "--command";
    public static final String KEY_GENERATION_SOURCES_KEY = "--sources";
    public static final String DIRECTORY_KEY = "--dir";
    public static final String UPDATE_MODE_KEY = "--mode";
    public static final String RESUME_ON_ERROR_KEY = "--resumeonerror";

    public static final String COMMAND_ADD = "add";
    public static final String COMMAND_REMOVE = "remove";
    public static final String COMMAND_GEN_SQL = "generatesql";
    public static final String UPDATE_MODE_FINGERPRINT = "fingerprint";
    public static final String UPDATE_MODE_DEBIAN_FINGERPRINT = "debianfingerprint";
    public static final String CSV_SEPARATOR = ",";

    {
        registerParameter(new Parameter(COMMAND_KEY, "Command to execute", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Command to execute. Use " + COMMAND_ADD + ", " + COMMAND_REMOVE + " or " + COMMAND_GEN_SQL + "."));
        registerParameter(new Parameter(UPDATE_MODE_KEY, "Update mode", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Specifies the format of block list data. Possible values are" + System.lineSeparator() +
                "    fingerprint       - If the input files shall be treated as CSV" + System.lineSeparator() +
                "                        files, where the first column contains" + System.lineSeparator() +
                "                        a SHA-256 hash of the DER encoded public" + System.lineSeparator() + 
                "                        key modulus." + System.lineSeparator() +
                "    debianfingerprint - If the input files shall be treated as a" + System.lineSeparator() +
                "                        Debian weak key block lists, where each line" + System.lineSeparator() +
                "                        is the fingerprint of a weak Debian key." + System.lineSeparator() +
                "                        See https://wiki.debian.org/SSLkeys" + System.lineSeparator() +
                "If not specified, the input files are treated as PEM-encoded public keys."));
        registerParameter(new Parameter(DIRECTORY_KEY, "Public key directory", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Directory with block list data."));
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
        return "updatepublickeyblocklist";
    }
    
    @Override
    public Set<String> getMainCommandAliases() {
        return new HashSet<String>(Arrays.asList("updatepublickeyblacklist"));
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");

        CryptoProviderTools.installBCProviderIfNotAvailable();

        try {
            final String command = parameters.get(COMMAND_KEY);
            final String importDirString = parameters.get(DIRECTORY_KEY);
            final boolean byFingerprint = UPDATE_MODE_FINGERPRINT.equals(parameters.get(UPDATE_MODE_KEY));
            final boolean byDebianFingerprint = UPDATE_MODE_DEBIAN_FINGERPRINT.equals(parameters.get(UPDATE_MODE_KEY));
            final boolean resumeOnError = parameters.containsKey(RESUME_ON_ERROR_KEY);

            // Get all files in the directory to add/remove to/from public key blacklist. 
            final File importDir = new File(importDirString);
            if (!importDir.isDirectory()) {
                log.error("'" + importDirString + "' is not a directory.");
                return CommandResult.CLI_FAILURE;
            }
            final File files[] = importDir.listFiles();
            if (files == null || files.length < 1) {
                log.info("No files in directory '" + importDir.getCanonicalPath() + "'. Nothing to do.");
                return CommandResult.SUCCESS; // Nothing to do is OK
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
            byte[] asn1Encodedbytes;
            long counter = 0;

            for (final File file : files) {
                state = STATUS_GENERALIMPORTERROR;
                try {
                    path = file.getAbsolutePath();
                    log.debug("Read file " + path);

                    if (COMMAND_ADD.equals(command)) {
                        if (byFingerprint) {
                            log.info("Read public key fingerprints file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            String[] tokens;
                            for (String line : lines) {
                                tokens = line.split(CSV_SEPARATOR);
                                if (tokens.length > 0) {
                                    fingerprint = tokens[0];
                                    state = addPublicKeyFingerprintToBlacklist(fingerprint);
                                    if (STATUS_OK != state) {
                                        log.info("Update public key block list failed on fingerprint: " + fingerprint); 
                                        break;
                                    }
                                }
                            }
                        } else if (byDebianFingerprint) {
                            log.info("Read Debian public key fingerprints file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            for (final String line : lines) {
                                final String trimmedLine = StringUtils.trim(line);
                                if (StringUtils.startsWith(trimmedLine, "#") || StringUtils.isEmpty(trimmedLine)) {
                                    continue;
                                }
                                if (trimmedLine.length() != 20) {
                                    state = STATUS_READ_ERROR;
                                    continue;
                                }
                                state = addPublicKeyFingerprintToBlacklist(trimmedLine);
                            }
                        } else {
                            log.info("Read public key file " + path);
                            asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(path));
                            if (null == (publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes))) {
                                state = STATUS_READ_ERROR;
                            } else {
                                state = addPublicKeyToBlacklist(publicKey);
                            }
                        }
                    } else if (COMMAND_REMOVE.equals(command)) {
                        if (byFingerprint) {
                            log.info("Remove public keys by fingerprints listed in file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            String[] tokens;
                            for (String line : lines) {
                                tokens = line.split(CSV_SEPARATOR);
                                if (tokens.length > 0) {
                                    fingerprint = tokens[0];
                                    log.info("Try to remove public key from public key block list (fingerprint=" + fingerprint + ").");
                                    try {
                                        state = removeFromBlacklist(PublicKeyBlacklistEntry.TYPE, fingerprint);
                                    } catch (BlacklistDoesntExistsException e) {
                                        // Do nothing, it was already printed to info
                                    }
                                    if (STATUS_OK != state) {
                                        log.info("remove public key block list failed on fingerprint: " + fingerprint);                                        
                                    }
                                }
                            }
                        } else if (byDebianFingerprint) {
                            log.info("Remove Debian public key fingerprints by file " + path);
                            reader = new FileReader(file);
                            lines = IOUtils.readLines(reader);
                            IOUtils.closeQuietly(reader);
                            for (final String line : lines) {
                                final String trimmedLine = StringUtils.trim(line);
                                if (StringUtils.startsWith(trimmedLine, "#") || StringUtils.isEmpty(trimmedLine)) {
                                    continue;
                                }
                                if (trimmedLine.length() != 20) {
                                    state = STATUS_READ_ERROR;
                                    continue;
                                }
                                state = removeFromBlacklist(PublicKeyBlacklistEntry.TYPE, trimmedLine);
                            }
                        } else {
                            log.info("Remove public key by file " + path);
                            asn1Encodedbytes = KeyTools.getBytesFromPublicKeyFile(FileTools.readFiletoBuffer(path));
                            if (null == (publicKey = KeyTools.getPublicKeyFromBytes(asn1Encodedbytes))) {
                                state = STATUS_READ_ERROR;
                            } else {
                                state = removePublicKeyToBlacklist(publicKey);
                            }
                        }
                    } else if (COMMAND_GEN_SQL.equals(command)) {
                        reader = new FileReader(file);
                        lines = IOUtils.readLines(reader);
                        IOUtils.closeQuietly(reader);
                        for (final String line : lines) {
                            if (StringUtils.isEmpty(line)) {
                                continue;
                            }
                            if (line.startsWith("#")) {
                                continue;
                            }
                            System.out.println(String.format("INSERT INTO `BlacklistData` VALUES (%d,NULL,NULL,0,'PUBLICKEY',0,'%s');",
                                    counter++, line.contains(",") ? line.split(",")[0] : line.trim()));
                        }
                        state = STATUS_OK;
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
                        throw new Exception("Update public key block list aborted --resumeonerror=" + resumeOnError);
                    }
                } catch (BlacklistExistsException e) {
                    log.error("Update public key block list failed: " + e.getMessage());
                    if (!resumeOnError) {
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                } catch (BlacklistDoesntExistsException e) {
                    log.info("Update public key block list failed: " + e.getMessage());
                    if (!resumeOnError) {
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                } catch (AuthorizationDeniedException e) {
                    log.info("Not authorized to update block list: " + e.getMessage());
                    if (!resumeOnError) {
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                } catch (Exception e) {
                    log.info("Update public key block list failed: " + e.getMessage(), e);
                    if (!resumeOnError) {
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                }
            }

            printSummary(importOk, readError, redundant, constraintViolation, generalImportError, command);
        } catch (Exception e) {
            log.error("Update public key block list aborted: " + e.getMessage(), e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        log.trace("<execute()");
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Updates the public key block list datastore.";
    }

    @Override
    public String getFullHelpText() {
        return "Add or remove public keys for which the CA should not issue certificates." + System.lineSeparator() +
               "Point to a directory of public keys or a list of fingerprints to be processed.";
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
    private int addPublicKeyToBlacklist(final PublicKey publicKey) throws Exception {
        log.trace(">addPublicKeyToBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
        entry.setFingerprint(publicKey);
        log.info("Try to add public key into public key blacklist (fingerprint=" + entry.getFingerprint() + ").");
        result = addToBlacklist(entry);
        log.trace("<addPublicKeyToBlacklist()");
        return result;
    }

    /**
     * Adds a fingerprint to the public key blacklist.
     * 
     * @param fingerprint the fingerprint to add, note the special conditions for this fingerprint see {@link PublicKeyBlacklistEntry#setFingerprint(PublicKey)}
     * @param keySpecification the key specification.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    private int addPublicKeyFingerprintToBlacklist(final String fingerprint) throws Exception {
        final PublicKeyBlacklistEntry entry = new PublicKeyBlacklistEntry();
        entry.setFingerprint(fingerprint.toLowerCase());
        log.info("Blocklisting public key by fingerprint (fingerprint=" + fingerprint + ").");
        return addToBlacklist(entry);
    }

    /**
     * Removes a public key from the public key blacklist.
     * 
     * @param publicKey the public key to remove.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    private int removePublicKeyToBlacklist(final PublicKey publicKey) throws Exception {
        log.trace(">removePublicKeyFromBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final String fingerprint = PublicKeyBlacklistEntry.createFingerprint(publicKey);
        log.info("Try to remove public key from public key block list (fingerprint=" + fingerprint + ").");
        result = removeFromBlacklist(PublicKeyBlacklistEntry.TYPE, fingerprint);
        log.trace("<removePublicKeyFromBlacklist()");
        return result;
    }

    /**
     * Adds a public key to the public key blacklist if a public key with that fingerprint does not exists already.
     * 
     * @param entry the public key blacklist entry.
     * @return {@link #STATUS_GENERALIMPORTERROR} if error, {@link #STATUS_CONSTRAINTVIOLATION} if already existing or {@link #STATUS_OK} if added.
     * @throws Exception any exception.
     */
    private int addToBlacklist(final PublicKeyBlacklistEntry entry) throws Exception {
        log.trace(">addToBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final BlacklistSessionRemote blacklistSession = EjbRemoteHelper.INSTANCE.getRemoteSession(BlacklistSessionRemote.class);
        try {
            blacklistSession.addBlacklistEntry(getAuthenticationToken(), entry);
            result = STATUS_OK;
        } catch (BlacklistExistsException e) {
            result = STATUS_CONSTRAINTVIOLATION;
            log.info("Public key block list entry with public key fingerprint " + entry.getFingerprint() + " already exists.");
            throw e;
        } catch (AuthorizationDeniedException e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Authorization denied to add public key to block list.");
            throw e;
        } catch (Exception e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Error while adding public key to block list: " + e.getMessage());
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
    private int removeFromBlacklist(final String type, final String value) throws Exception {
        log.trace(">removeFromBlacklist()");
        int result = STATUS_GENERALIMPORTERROR;
        final BlacklistSessionRemote blacklistSession = EjbRemoteHelper.INSTANCE.getRemoteSession(BlacklistSessionRemote.class);
        try {
            blacklistSession.removeBlacklistEntry(getAuthenticationToken(), type, value);
            result = STATUS_OK;
        } catch (BlacklistDoesntExistsException e) {
            result = STATUS_CONSTRAINTVIOLATION;
            log.info("Public key block list entry with public key fingerprint " + value + " does not exist.");
            throw e;
        } catch (AuthorizationDeniedException e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Authorization denied to remove public key from block list.");
            throw e;
        } catch (Exception e) {
            result = STATUS_GENERALIMPORTERROR;
            log.info("Error while removing public key from block list: " + e.getMessage());
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
            final int generalImportError, final String command) {
        // Print resulting statistics
        log.info("\n"+command+" summary:");
        log.info(importOk + " public key block list entries were processed with success (STATUS_OK)");
        if (readError > 0) {
            log.info(readError + " public key block list entries could not be parsed (STATUS_READERROR)");
        }
        if (redundant > 0) {
            log.info(redundant + " public key block list entries were already present in the database (STATUS_REDUNDANT)");
        }
        if (constraintViolation > 0) {
            log.info(constraintViolation + " public key block list entries could not be stored (STATUS_CONSTRAINTVIOLATION)");
        }
        if (generalImportError > 0) {
            log.info(generalImportError + " public key block list entries were not imported due to other errors (STATUS_GENERALIMPORTERROR)");
        }
    }
}
