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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;

/**
 * Tools to handle calls with Java Process API ({@link https://docs.oracle.com/javase/8/docs/api/java/lang/Process.html}.
 *
 * @version $Id: ExternalProcessTools.java 27126 2017-12-16 09:28:54Z anjakobs $
 */
public final class ExternalProcessTools {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalProcessTools.class);

    /** Internal localization of logs and errors. */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Literal for the (platform dependent) line separator. */
    private static final String LINE_SEPARATOR = System.getProperty("line.separator");

    /** Literal for place holder for the certificate issued */
    public static final String PLACE_HOLDER_CERTIFICATE = "%cert%";

    /** Literal for default MS Windows shell. */
    public static final String WINDOWS_SHELL = "cmd.exe";

    /** Literal for default MS Windows shell options. */
    public static final String WINDOWS_SHELL_OPTIONS = "/c";

    /** Literal for default Unix shell. */
    public static final String UNIX_SHELL = "/bin/sh";

    /** Literal for default Unix shell options. */
    public static final String UNIX_SHELL_OPTIONS = "-c";

    /** Literal for exit code label / prefix. */
    public static final String EXIT_CODE_PREFIX = "Exit code: ";

    /** Literal for STDOUT label to log the external out streams . */
    public static final String STDOUT_PREFIX = "STDOUT: ";

    /** Literal for ERROUT label to log the external out streams . */
    public static final String ERROUT_PREFIX = "ERROUT: ";

    /**
     * Builds the platform dependent external command array:
     * - field at index 0 is the interpreter,
     * - field at index 1 is the one and only parameter of the interpreter,
     * - field at index 2 must contain the complete external command, including pipes, chains, sub-shells, etc. and is appended later.
     * 
     * @param the external command or script
     * @return the command array as list.
     */
    protected static final List<String> buildShellCommand(final String cmd) {
        final List<String> result = new ArrayList<String>();
        if (SystemUtils.IS_OS_WINDOWS) {
            result.add(WINDOWS_SHELL);
            result.add(WINDOWS_SHELL_OPTIONS);
        } else {
            result.add(UNIX_SHELL);
            result.add(UNIX_SHELL_OPTIONS);
        }
        if (log.isDebugEnabled()) {
            log.debug("Use platform shell command for " + SystemUtils.OS_NAME + " : " + result);
        }
        if (result.size() == 2) {
            result.add(cmd);
        }
        return result;
    }

    /**
     * Writes a byte array to a temporary file and launches the given external command with the file as first argument 
     * if {@link #PLACE_HOLDER_CERTIFICATE} is not specified as argument, or pipes the byte array into the command if 
     * {@link #PLACE_HOLDER_CERTIFICATE} is used as argument.
     * 
     * @see {@link ExternalProcessTools#launchExternalCommand(String, byte[], boolean, boolean, boolean, boolean, List, String)}.
     * 
     * @param cmd The command to run.
     * @param bytes The buffer with content to write to file or pipe to stdin.
     * @param failOnCode Determines if the method should fail on a non-zero exit code.
     * @param failOnOutput Determines if the method should fail on output to standard error.
     * @param arguments the command arguments (optional), may contain the placeholder '%cert' to
     * retrieve data from stdin. 
     * @param filePrefix a prefix to prepend to the temporary filename, typically the name of the caller.
     * @return the output of the command (stdout, any stderr and the exit code).
     * @throws ExternalProcessException if the temporary file could not be written or the external process fails.
     */
    public static final List<String> launchExternalCommand(final String cmd, final byte[] bytes, final boolean failOnCode, final boolean failOnOutput,
            final List<String> arguments, final String filePrefix) throws ExternalProcessException {
        return launchExternalCommand(cmd, bytes, failOnCode, failOnOutput, false, false, arguments, filePrefix);
    }

    /**
     * Writes a byte array to a temporary file and launches the given external command with the file as first argument if 
     * {@link #PLACE_HOLDER_CERTIFICATE} is not specified as one of the arguments, or pipes the bytes array into the command 
     * if {@link #PLACE_HOLDER_CERTIFICATE} is used as argument. 
     * 
     * <p>The method will, depending on the parameters given, fail with {@link ExternalProcessException} if output to standard
     * error was detected or the if the command  returns with a non-zero exit code.
     * 
     * @param cmd The command to run.
     * @param bytes The buffer with content to write to the file to pipe to stdin.
     * @param failOnCode Determines if the method should fail on a non-zero exit code.
     * @param failOnOutput Determines if the method should fail on output to standard error.
     * @param logStdOut if the scripts STDOUT should be logged as info.
     * @param logErrOut if the scripts ERROUT should be logged as info.
     * @param arguments the command arguments (optional), may contain the placeholder '%cert' to
     * retrieve data from stdin.
     * @param filePrefix a prefix to prepend to the temporary filename, typically the name of the caller.
     * @return the output of the command (stdout, any stderr and the exit code).
     * @throws ExternalProcessException if the temporary file could not be written or the external process fails.
     */
    public static final List<String> launchExternalCommand(final String cmd, final byte[] bytes, final boolean failOnCode, final boolean failOnOutput,
            final boolean logStdOut, final boolean logErrOut, final List<String> arguments, final String filePrefix) throws ExternalProcessException {
        final long startTime = System.currentTimeMillis();
        int exitStatus = -1;
        final List<String> result = new ArrayList<String>();
        final boolean writeFileToDisk = !arguments.contains(PLACE_HOLDER_CERTIFICATE);
        File file = null;
        if (writeFileToDisk) {
            final String filename = filePrefix + '-' + System.currentTimeMillis();
            file = writeTemporaryFileToDisk(filename, /* use .tmp as file extension */ null, bytes);
        }
        // Execute external script or command with PEM in STDIN or full path of temporary file as first argument.
        String filename = null;
        try {
            final List<String> cmdTokens = Arrays.asList(cmd.split("\\s"));
            // Write file to disk or process place holder with PEM certificates and build shell command.
            if (writeFileToDisk) {
                filename = file.getCanonicalPath();
                arguments.add(0, filename);
            } else {
                // Only works with PEM X.509 certificates at the time as used in ExternalCommandCertificateValidator (not by CRL publishers).
                final List<Certificate> certificates = new ArrayList<Certificate>();
                certificates.add(CertTools.getCertfromByteArray(bytes));
                final byte[] testPemBytes = CertTools.getPemFromCertificateChain(certificates);
                String pemString = new String(testPemBytes);
                pemString = pemString.substring(pemString.indexOf(LINE_SEPARATOR) + 1, pemString.length());
                pemString = pemString.substring(pemString.indexOf(LINE_SEPARATOR) + 1, pemString.length());
                if (log.isDebugEnabled()) {
                    log.debug("Using certificates:\n" + pemString);
                }
                arguments.remove(arguments.indexOf(PLACE_HOLDER_CERTIFICATE));

                if (SystemUtils.IS_OS_WINDOWS) {
                    // Broken. Command cannot be executed.
                    cmdTokens.set(0, "echo \"" + pemString + "\" | " + cmdTokens.get(0));
                    /*
                     * Hack needed for Windows, where Runtime.exec won't consistently encapsulate arguments, leading to arguments
                     * containing spaces (such as Subject DNs) sometimes being parsed as multiple arguments. Bash, on the other hand,
                     * won't parse quote surrounded arguments. 
                     */
                    qouteArguments(arguments);
                } else {
                    cmdTokens.set(0, "echo -n \"" + pemString + "\" | " + cmdTokens.get(0));
                }
            }
            List<String> cmdArray = new ArrayList<String>();
            cmdArray.addAll(cmdTokens);
            cmdArray.addAll(arguments);
            if (!writeFileToDisk) {
                cmdArray = buildShellCommand(StringUtils.join(cmdArray, " "));
            }
            if (log.isDebugEnabled()) {
                log.debug("Process external command for " + getPlatformString() + ": " + cmdArray);
            }
            // Launch external process.
            final Process externalProcess = Runtime.getRuntime().exec(cmdArray.toArray(new String[] {}), null, null);
            externalProcess.getOutputStream().close(); // prevent process from trying to wait for user input (e.g. prompt for overwrite, or similar)
            final BufferedReader stdError = new BufferedReader(new InputStreamReader(externalProcess.getErrorStream()));
            final BufferedReader stdOut = new BufferedReader(new InputStreamReader(externalProcess.getInputStream()));
            String line = null;
            while ((line = stdOut.readLine()) != null) { // NOPMD: Required under win32 to avoid lock
                if (logStdOut) {
                    result.add(STDOUT_PREFIX + line);
                }
            }
            String stdErrorOutput = null;
            // Check error code and the external applications output to STDERR.
            exitStatus = externalProcess.waitFor();
            result.add(0, EXIT_CODE_PREFIX + exitStatus);
            if (((exitStatus != 0) && failOnCode) || (stdError.ready() && failOnOutput)) {
                if (writeFileToDisk && file.exists()) {
                    file.delete();
                }
                String errTemp = null;
                while (stdError.ready() && (errTemp = stdError.readLine()) != null) {
                    if (logErrOut) {
                        result.add(ERROUT_PREFIX + errTemp);
                    }
                    if (stdErrorOutput == null) {
                        stdErrorOutput = errTemp;
                    } else {
                        stdErrorOutput += "\n" + errTemp;
                    }
                }
                String msg = intres.getLocalizedMessage("process.errorexternalapp", cmd);
                if (stdErrorOutput != null) {
                    msg += " - " + stdErrorOutput + " - " + filename;
                }
                throw new ExternalProcessException(msg, result);
            }
        } catch (CertificateParsingException | CertificateEncodingException e) { // Should never happen (is only used for certificates not for CRL.)
            throw new ExternalProcessException("Certificate could not parsed or encoded." + cmd, e, result);
        } catch (IOException e) { // if the command could not be found
            result.add(0, EXIT_CODE_PREFIX + exitStatus);
            if (logErrOut) {
                result.add(ERROUT_PREFIX + e.getMessage());
            }
            throw new ExternalProcessException(intres.getLocalizedMessage("process.errorexternalapp", cmd), e, result);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExternalProcessException(intres.getLocalizedMessage("process.errorexternalapp", cmd), e, result);
        } finally {
            if (writeFileToDisk && file != null && file.exists() && !file.delete()) {
                // Remove temporary file or schedule for delete if delete fails.
                file.deleteOnExit();
                log.info(intres.getLocalizedMessage("process.errordeletetempfile", filename));
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("Time spent to execute external command (writeFileToDisk=" + writeFileToDisk + "): " + (System.currentTimeMillis() - startTime)
                    + "ms.");
        }
        return result;
    }

    public static final String getPlatformString() {
        return SystemUtils.OS_NAME + " / " + SystemUtils.OS_VERSION + " - " + SystemUtils.OS_ARCH;
    }

    /**
     * Writes the byte array given as argument, to a temporary file on disk.
     * 
     * @param filePrefix the file prefix of to use as a part of the filename.
     * @param fileExtension the file extension (including the leading dot) of the file to be created, or null 
     * to use the default file extension (.tmp).
     * @param bytes a byte array containing the bytes to be written to disk.
     * @return a {@link File} object, never null.
     * @throws ExternalProcessException if the file could not be written to disk
     */
    public static final File writeTemporaryFileToDisk(final String filePrefix, final String fileExtension, final byte[] bytes)
            throws ExternalProcessException {
        try {
            final File file = File.createTempFile(filePrefix + '-', fileExtension);
            try (final FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(bytes);
            }
            if (log.isDebugEnabled()) {
                log.debug("Wrote file " + file.getName() + " (" + bytes.length + " bytes) to disk.");
            }
            return file;
        } catch (final IOException e) {
            log.error(intres.getLocalizedMessage("process.errortempfile"));
            throw new ExternalProcessException(e);
        }
    }
    
    /**
     * Extracts the exit code in the list (at index 0 prefixed with #EXIT_CODE_PREFIX).
     * @param out the output of the external process.
     * 
     * @return the exit code.
     */
    public static final Integer extractExitCode(final List<String> out) {
        Integer result = null;
        if (CollectionUtils.isNotEmpty(out)) {
            result = Integer.parseInt(out.get(0).replaceFirst(ExternalProcessTools.EXIT_CODE_PREFIX, StringUtils.EMPTY));
        }
        return result;
    }

    /**
     * Checks if the list contains logging to ERROUT.
     * @param out the output of the external process.
     * @return true if the list contains logging to ERROUT.
     */
    public static final boolean containsErrout(final List<String> out) {
        if (CollectionUtils.isNotEmpty(out) && out.size() > 1) {
            for (int i= 1,j=out.size();i<j;i++) {
                if (out.get(i).startsWith(ERROUT_PREFIX)) {
                    return true;
                }
            }
        }
        return false;
    }
    
    /**
     * Quotes the arguments list.
     * @param arguments the arguments list.
     */
    private static final void qouteArguments(final List<String> arguments) {
        for (int i = 0; i < arguments.size(); i++) {
            String argument = arguments.get(i);
            //Add quotes to encapsulate argument. 
            if (!argument.startsWith("\"") && !argument.endsWith("\"")) {
                arguments.set(i, "\"" + argument + "\"");
            }
        }
    }

    /**
     * Avoid instantiation.
     */
    private ExternalProcessTools() {
    }
}
