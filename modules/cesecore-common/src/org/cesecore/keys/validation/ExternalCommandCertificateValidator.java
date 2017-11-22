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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.profiles.Profile;
import org.cesecore.util.CertTools;

/**
 * External command certificate validator for multiple platforms.
 * 
 * @version $Id: ExternalCommandCertificateValidator.java 26865 2017-10-22 20:58:48Z anjakobs $
 */
public class ExternalCommandCertificateValidator extends CertificateValidatorBase {

    private static final long serialVersionUID = -135859158339811678L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalCommandCertificateValidator.class);

    /** The validator type. */
    private static final String TYPE_IDENTIFIER = "EXTERNAL_CERTIFICATE_VALIDATOR";

    /** Literal for place holder for a custom platform command. */
    public static final String PLACE_HOLDER_CUSTOM_PLATFORM_COMMAND = "%custom%";

    /** Literal for place holder for the certificate issued */
    public static final String PLACE_HOLDER_CERTIFICATE = "%cert%";

    /** Literal for place holder for the CA certificate chain of the issued certificate. */
    public static final String PLACE_HOLDER_CA_CHAIN = "%chain%";

    /** Literal for default MS Windows shell. */
    public static final String WINDOWS_SHELL = "cmd.exe";

    /** Literal for default MS Windows shell options. */
    public static final String WINDOWS_SHELL_OPTIONS = "/c";

    /** Literal for default Unix shell. */
    public static final String UNIX_SHELL = "/bin/sh";

    /** Literal for default Unix shell options. */
    public static final String UNIX_SHELL_OPTIONS = "-c";

    /** Literal for default Mac shell. */
    public static final String MAC_SHELL = "/bin/sh";

    /** Literal for default Mac shell options. */
    public static final String MAC_SHELL_OPTIONS = "-c";

    /** Literal for exit code label / prefix. */
    public static final String EXIT_CODE_PREFIX = "Exit code: ";

    /** Literal for STDOUT label to log the external out streams . */
    public static final String STDOUT_PREFIX = "STDOUT: ";

    /** Literal for ERROUT label to log the external out streams . */
    public static final String ERROUT_PREFIX = "ERROUT: ";

    /** View template in /ca/editExternalCommandCertificateValidator.xhtml */
    protected static final String TEMPLATE_FILE = "editExternalCommandCertificateValidator.xhtml";

    /** Literal for external command storage key. */
    protected static final String EXTERNAL_COMMAND = "externalCommand";

    /** Literal for external log to STDOUT storage key. */
    protected static final String LOG_STANDARD_OUT = "logStandardOut";

    /** Literal for external log to ERROUT storage key. */
    protected static final String LOG_ERROR_OUT = "logErrorOut";

    /** Holds the test certificates uploaded by the user. */
    private List<Certificate> testCertificates;

    /** Holds the STDOUT and ERROUT by the test of the external command. */
    private String testStandardAndErrorOut;

    /**
     * Public constructor needed for deserialization.
     */
    public ExternalCommandCertificateValidator() {
        super();
        init();
    }

    /**
     * Creates a new instance.
     */
    public ExternalCommandCertificateValidator(final String name) {
        super(name);
        init();
    }

    /**
     * Creates a new instance with the same attributes as the given one.
     * @param validator the base key validator to load.
     */
    public ExternalCommandCertificateValidator(final CertificateValidatorBase validator) {
        super(validator);
    }

    /**
     * Initializes uninitialized data fields.
     */
    @Override
    public void init() {
        super.init();
        if (null == data.get(EXTERNAL_COMMAND)) {
            setExternalCommand(StringUtils.EMPTY);
        }
        if (data.get(LOG_STANDARD_OUT) == null) {
            setLogStandardOut(false);
        }
        if (data.get(LOG_ERROR_OUT) == null) {
            setLogErrorOut(false);
        }
        // Initialize UI properties.
//        uiProperties = new DynamicUiPropertiesBase(data);
//        uiProperties.addProperty(new DynamicUiProperty<String>(EXTERNAL_COMMAND, StringUtils.EMPTY));
//        uiProperties.addProperty(new DynamicUiProperty<Boolean>(LOG_STANDARD_OUT, Boolean.FALSE)); 
//        uiProperties.addProperty(new DynamicUiProperty<Boolean>(LOG_ERROR_OUT, Boolean.FALSE)); 
    }

    @Override
    public String getTemplateFile() {
        return TEMPLATE_FILE;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        super.upgrade();
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("validator.implementation.certificate.external", new Float(getVersion())));
            init();
        }
    }

    @Override
    public List<String> validate(final CA ca, final Certificate certificate)
            throws ValidatorNotApplicableException, ValidationException, CertificateException {
        List<String> messages = new ArrayList<String>();
        log.debug("Validating certificate with external command " + getExternalCommand());
        if (log.isDebugEnabled()) {
            log.debug("Validating certificate with external command (cert):" + certificate);
        }
        // Add CA certificate chain, that may be processed.
        final List<Certificate> certificates;
        if (ca != null) {
            certificates = new ArrayList<Certificate>(ca.getCertificateChain());
        } else {
            certificates = new ArrayList<Certificate>();
        }
        certificates.set(0, certificate);

        final String[] cmdTokens = buildPlatformCommand(certificates);
        final List<String> out = launchExternalCommand(cmdTokens, isLogStandardOut(), isLogErrorOut());

        // Something bad must have happened so that no exit code is returned.
        if (out.size() < 1) {
            messages.add("Invalid: External command could not be processed. Fatal error: " + Arrays.toString(cmdTokens));
        } else {
            final int exitCode = Integer.parseInt(out.get(0).replaceFirst(EXIT_CODE_PREFIX, StringUtils.EMPTY));
            if (exitCode > 0) {
                // Validation failed.
                messages.add("Invalid: External command terminated with exit code larger than 0. Command failed.");
            }
        }
        return messages;
    }

    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.certificate.external");
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return ExternalCommandCertificateValidator.class;
    }

    public void setExternalCommand(String command) {
        data.put(EXTERNAL_COMMAND, command);
    }

    public String getExternalCommand() {
        return (String) data.get(EXTERNAL_COMMAND);
    }

    public void setLogStandardOut(boolean state) {
        data.put(LOG_STANDARD_OUT, Boolean.valueOf(state));
    }

    public boolean isLogStandardOut() {
        return ((Boolean) data.get(LOG_STANDARD_OUT)).booleanValue();
    }

    public void setLogErrorOut(boolean state) {
        data.put(LOG_ERROR_OUT, Boolean.valueOf(state));
    }

    public boolean isLogErrorOut() {
        return ((Boolean) data.get(LOG_ERROR_OUT)).booleanValue();
    }

    /**
     * Tests the external command with the uploaded test certificate (chain).
     * @return a list with size > 0 and the exit code in field with index 0 and STDOUT and ERROR appended subsequently.
     * @throws Exception any exception.
     */
    public List<String> testExternalCommandCertificateValidatorAction() throws Exception {
        log.info("Test external command certificate validator: " + getProfileName());
        final String[] cmdTokens = buildPlatformCommand(getTestCertificates());
        final List<String> out = launchExternalCommand(cmdTokens, isLogStandardOut(), isLogErrorOut());
        return out;
    }

    /**
     * Gets the list of test certificates uploaded by the user.
     * @return the list of test certificates.
     */
    public List<Certificate> getTestCertificates() {
        return testCertificates;
    }

    public void setTestCertificates(List<Certificate> testCertificates) {
        this.testCertificates = testCertificates;
    }

    /**
     * Gets the result of the test of the external command which is displayed to the user.
     * @return the list of lines.
     */
    public String getTestStandardAndErrorOut() {
        return testStandardAndErrorOut;
    }

    public void setTestStandardAndErrorOut(String testStandardAndErrorOut) {
        this.testStandardAndErrorOut = testStandardAndErrorOut;
    }

    /**
     * Builds the platform dependent external command array:
     * - field at index 0 is the interpreter,
     * - field at index 1 is the one and only parameter of the interpreter,
     * - field at index 2 must contain the complete external command, including pipes, chains, sub-shells, etc. and is appended later.
     * @return the command array as list.
     */
    public final List<String> buildShellCommand() {
        final List<String> cmd = new ArrayList<String>();
        if (!getExternalCommand().startsWith(PLACE_HOLDER_CUSTOM_PLATFORM_COMMAND)) {
            if (log.isDebugEnabled()) {
                log.debug("Detecting platform: " + SystemUtils.OS_NAME + " - " + SystemUtils.OS_VERSION);
            }
            if (SystemUtils.IS_OS_WINDOWS) {
                cmd.add(WINDOWS_SHELL);
                cmd.add(WINDOWS_SHELL_OPTIONS);
            } else if (SystemUtils.IS_OS_UNIX | SystemUtils.IS_OS_LINUX | SystemUtils.IS_OS_AIX | SystemUtils.IS_OS_HP_UX
                    | SystemUtils.IS_OS_SOLARIS) {
                cmd.add(UNIX_SHELL);
                cmd.add(UNIX_SHELL_OPTIONS);
            } else if (SystemUtils.IS_OS_MAC) {
                cmd.add(MAC_SHELL);
                cmd.add(MAC_SHELL_OPTIONS);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Platform could not be detected to build external command: " + SystemUtils.OS_NAME + " - " + SystemUtils.OS_VERSION);
                }
                // NOOP
            }
            if (cmd.size() == 2) {
                cmd.add(getExternalCommand());
            }
        } else {
            // NOOP Is done later in buildPatformCommand.
        }
        return cmd;
    }

    /**
     * Builds the platform independent or dependent command with all place holders processed.
     * @param certificates the list of certificates to insert.
     * @return the command array with the external command.
     * @throws CertificateException if one of the certificates could not be parsed.
     */
    public String[] buildPlatformCommand(final List<Certificate> certificates) throws CertificateException {
        // Detect platform and build base command string.
        final List<String> cmdList = buildShellCommand();
        String cmd = getExternalCommand();
        log.info("External command certificate validator command: " + cmdList + " - " + cmd);
        if (cmdList.size() == 3) {
            // NOOP 
            // Command was entered including shell and shell options and command itself.
        } else {
            // Is custom command or platform could not be detected.
            // -> First two string must become shell and shell options.
            try {
                cmd = cmd.replaceFirst(PLACE_HOLDER_CUSTOM_PLATFORM_COMMAND + " ", StringUtils.EMPTY);
                final String shell = cmd.substring(0, cmd.indexOf(" "));
                cmd = cmd.replaceFirst(shell + " ", StringUtils.EMPTY);
                cmdList.add(shell);
                if (cmd.indexOf(" ") > 0) {
                    final String shellOptions = cmd.substring(0, cmd.indexOf(" "));
                    cmd = cmd.replaceFirst(shellOptions + " ", StringUtils.EMPTY);
                    cmdList.add(shellOptions);
                }
                cmdList.add(cmd);
            } catch (Exception e) {
                log.warn("Could not parse external command for certificate validator " + getProfileName() + ": " + e.getMessage(), e);
            }
        }
        final String[] cmdTokens = cmdList.toArray(new String[] {});
        if (log.isDebugEnabled()) {
            log.debug("Built platform dependent command: " + Arrays.toString(cmdTokens));
        }
        if (null != certificates) {
            if (log.isDebugEnabled()) {
                log.debug("Process test certificates: " + certificates);
            }
            for (int i = 0, j = cmdTokens.length; i < j; i++) {
                if (cmdTokens[i].contains(PLACE_HOLDER_CERTIFICATE)) {
                    try {
                        // Replace certificate place holder.
                        // ECA-6051 Re-factor: find better way for PEM, or better way at all.
                        final List<Certificate> userCertificates = new ArrayList<Certificate>();
                        userCertificates.add(certificates.get(0));
                        final byte[] testPemBytes = CertTools.getPemFromCertificateChain(userCertificates);
                        String pemString = new String(testPemBytes); //baos.toByteArray()
                        pemString = pemString.substring(pemString.indexOf(System.getProperty("line.separator")) + 1, pemString.length());
                        pemString = pemString.substring(pemString.indexOf(System.getProperty("line.separator")) + 1, pemString.length());
                        cmdTokens[i] = cmdTokens[i].replace(PLACE_HOLDER_CERTIFICATE, pemString);
                        if (log.isDebugEnabled()) {
                            log.debug("Built platform dependent command(" + PLACE_HOLDER_CERTIFICATE + "): " + Arrays.toString(cmdTokens));
                        }
                    } catch (CertificateEncodingException e) {
                        log.warn("Could not encode certificate to validate: " + e.getMessage(), e);
                    }
                }
                if (cmdTokens[i].contains(PLACE_HOLDER_CA_CHAIN) && certificates.size() > 1) {
                    // ECA-6051 Impl. CA-chain replacement.
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Test certificates are NULL.");
            }
        }
        return cmdTokens;
    }

    /**
     * Launches the external command.
     * @param cmdTokens the command array.
     * @param logStandardOut true if STDOUT shall be logged.
     * @param logErrorOut true if ERROUT shall be logged.
     * @return list with size > 0 and the exit code in field with index 0 and STDOUT and ERROR appended subsequently.
     */
    public final List<String> launchExternalCommand(final String[] cmdTokens, final boolean logStandardOut, final boolean logErrorOut) {
        final ProcessBuilder processBuilder = new ProcessBuilder(cmdTokens);
        Process process = null;
        final List<String> out = new ArrayList<String>();
        int exitStatus = -1;
        try {
            process = processBuilder.start();
            try (final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String s;
                while ((s = reader.readLine()) != null) {
                    s = STDOUT_PREFIX + s;
                    out.add(s);
                    if (logStandardOut) {
                        log.info(s);
                    }
                }
            } catch (IOException e1) {
                log.warn("Error while printing STDOUT to log: " + e1.getMessage(), e1);
            }
            try (final BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String s;
                while ((s = reader.readLine()) != null) {
                    s = ERROUT_PREFIX + s;
                    out.add(s);
                    if (logErrorOut) {
                        log.info(s);
                    }
                }
            } catch (IOException e1) {
                log.warn("Error while printing ERROUT to log: " + e1.getMessage(), e1);
            }
            process.waitFor();
            exitStatus = process.exitValue();
            log.info("External process terminated with exit status " + exitStatus);
        } catch (IOException e) {
            log.warn("IO Exception while calling external process: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            log.warn("Process is interrupted by calling external process: " + e.getMessage(), e);
        } catch (Exception e) {
            log.warn("Other Exception thrown while calling external process: " + e.getMessage(), e);
        } catch (Error e) {
            log.warn("Error thrown while calling external process: " + e.getMessage(), e);
        } finally {
            // NOOP
        }
        out.add(0, EXIT_CODE_PREFIX + exitStatus);
        return out;
    }
}
