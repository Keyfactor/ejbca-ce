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
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.profiles.Profile;
import org.cesecore.util.ExternalProcessException;
import org.cesecore.util.ExternalProcessTools;

/**
 * External command certificate validator for multiple platforms.
 *
 * @version $Id$
 */
public class ExternalCommandCertificateValidator extends CertificateValidatorBase {

    private static final long serialVersionUID = -135859158339811678L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalCommandCertificateValidator.class);

    public static final float LATEST_VERSION = 4F;

    /** The validator type. */
    private static final String TYPE_IDENTIFIER = "EXTERNAL_CERTIFICATE_VALIDATOR";

    /** View template in /ca/editExternalCommandCertificateValidator.xhtml */
    protected static final String TEMPLATE_FILE = "editExternalCommandCertificateValidator.xhtml";

    /** Literal for external command storage key. */
    protected static final String EXTERNAL_COMMAND = "externalCommand";

    /** Literal for fail on error code storage key. */
    protected static final String FAIL_ON_ERROR_CODE = "failOnErrorCode";

    /** Literal for fail on standard error storage key. */
    protected static final String FAIL_ON_STANDARD_ERROR = "failOnStandardError";

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
    }

    /**
     * Creates a new instance.
     */
    public ExternalCommandCertificateValidator(final String name) {
        super(name);
    }

    /**
     * Initializes uninitialized data fields.
     */
    @Override
    public void init() {
        super.init();
        if (data.get(EXTERNAL_COMMAND) == null) {
            setExternalCommand(StringUtils.EMPTY);
        }
        if (data.get(FAIL_ON_ERROR_CODE) == null) {
            setFailOnErrorCode(true);
        }
        if (data.get(FAIL_ON_STANDARD_ERROR) == null) {
            setFailOnStandardError(true);
        }
        if (data.get(LOG_STANDARD_OUT) == null) {
            setLogStandardOut(true);
        }
        if (data.get(LOG_ERROR_OUT) == null) {
            setLogErrorOut(true);
        }
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
    public List<String> validate(final CA ca, final Certificate certificate, final ExternalScriptsWhitelist externalScriptsWhitelist)
            throws ValidatorNotApplicableException, ValidationException, CertificateException {
        final List<String> messages = new ArrayList<String>();
        log.debug("Validating certificate with external command " + getExternalCommand());
        if (log.isDebugEnabled()) {
            log.debug("Validating certificate with external command (cert):" + certificate);
        }
        // Add CA certificate chain, that may be processed.
        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        final String cmd = getExternalCommand();
        final List<String> out = new ArrayList<String>();
        // Run external scripts (is used by publishers as well, writes certificate to disk!).
        try {
            out.addAll(runExternalCommandInternal(cmd, externalScriptsWhitelist, certificates));
        } catch(ExternalProcessException e) {
            throw new ValidatorNotApplicableException( "External command could not be called, because it does not exit, access was denied or another severe error occured.");
        }
        // Validator was applicable but something bad must have happened, no exit code was returned -> validation failed.
        boolean broken = false;
        if (CollectionUtils.isNotEmpty(out)) {
            try {
                final int exitCode = Integer.parseInt(out.get(0).replaceFirst(ExternalProcessTools.EXIT_CODE_PREFIX, StringUtils.EMPTY));
                if (exitCode > 0 && isFailOnErrorCode()) { // Validation failed: -1 is command could not be found or access denied.
                    messages.add("Invalid: External command exit code was " + exitCode + ". Command failed.");
                } else if (isFailOnErrorCode() && ExternalProcessTools.containsErrout(out)) {
                    messages.add("Invalid: External command logged to ERROUT. Exit code was " + exitCode + ". Command failed.");
                }
            } catch(Exception e2) { // In case exit code could not be parsed.
                broken = true;
            }
        } else {
            broken = true;
        }
        if (broken) {
            messages.add("Invalid: External command could not be initiated: '" + cmd + "'. Command failed.");
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

    public void setFailOnErrorCode(boolean state) {
        data.put(FAIL_ON_ERROR_CODE, Boolean.valueOf(state));
    }

    public boolean isFailOnErrorCode() {
        return ((Boolean) data.get(FAIL_ON_ERROR_CODE)).booleanValue();
    }

    public void setFailOnStandardError(boolean state) {
        data.put(FAIL_ON_STANDARD_ERROR, Boolean.valueOf(state));
    }

    public boolean isFailOnStandardError() {
        return ((Boolean) data.get(FAIL_ON_STANDARD_ERROR)).booleanValue();
    }

    /**
     * Tests the external command with the uploaded test certificate (chain).
     * @return a list with size > 0 and the exit code in field with index 0 and STDOUT and ERROR appended subsequently.
     * @throws CertificateException if one of the certificates could not be parsed.
     * @throws ValidatorNotApplicableException if the validator could not be applicated (wrong CA or key type, external script path is not in white list).
     * @throws ExternalProcessException if the external script path does not exist or accessible or the script call fails otherwise.
     */
    public List<String> testExternalCommandCertificateValidatorAction() throws CertificateEncodingException, ValidatorNotApplicableException, ExternalProcessException {
        final List<String> out = new ArrayList<String>();
        if (CollectionUtils.isNotEmpty(getTestCertificates())) {
            log.info("Test external command certificate validator: " + getProfileName());
            out.addAll(runExternalCommandInternal(getExternalCommand(), ExternalScriptsWhitelist.permitAll(), getTestCertificates()));
        }
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

    public String getPlatform() {
        return ExternalProcessTools.getPlatformString();
    }

    /**
     * Runs the external command
     * @param externalCommand the external command.
     * @param certificates the list of certificates.
     * @return a string list holding exit code at index 0, and the STDOUT and ERROUT appended.
     * @throws CertificateEncodingException if the certificates could not be encoded.
     */
    private List<String> runExternalCommandInternal(String externalCommand, final ExternalScriptsWhitelist externalScriptsWhitelist,
            final List<Certificate> certificates) throws CertificateEncodingException, ExternalProcessException, ValidatorNotApplicableException {
        final String cmd = extractCommand(externalCommand);
        if (!externalScriptsWhitelist.isPermitted(cmd)) {
            throw new ValidatorNotApplicableException("A whitelist has been enabled, but the command " + cmd + " is not on the whitelist.");
        }
        // Test if specified script file exists and is executable (hits files and symbolic links, but no aliases).
        if (StringUtils.isNotBlank(cmd)) {
            if (!(new File(cmd)).canExecute()) {
                // EXTERNALCERTIFICATEVALIDATORTESTPATHMISSING
                final String msg = intres.getLocalizedMessage("process.commandnotfound", cmd);
                log.warn(msg);
                throw new ExternalProcessException(msg);
            }
        }
        final List<String> arguments = extractArguments(externalCommand);
        final List<String> out = new ArrayList<String>();
        try {
            out.addAll(ExternalProcessTools.launchExternalCommand(cmd, certificates.get(0).getEncoded(),
                    isFailOnErrorCode(), isFailOnStandardError(), isLogStandardOut(), isLogErrorOut(), arguments, ExternalCommandCertificateValidator.class.getName()));
        } catch(ExternalProcessException e) {
            log.info("Could not call external command '" + cmd + "' with arguments " + arguments + " sucessfully: " + e.getMessage(), e);
            if (e.getOut() != null) {
                out.addAll(e.getOut());
            }
        }
        return out;
    }

    private final String extractCommand(String cmd) {
        cmd = cmd.trim();
        final int index = cmd.indexOf(" ");
        if (index > 0) {
            cmd  = cmd.substring(0, index).trim();
        }
        if (log.isDebugEnabled()) {
            log.debug("Command extracted: " + cmd);
        }
        return cmd;
    }

    private final List<String> extractArguments(String cmd) {
        cmd = cmd.trim();
        final List<String> arguments = new ArrayList<String>();
        final int index = cmd.indexOf(" ");
        if (index > 0) {
            arguments.addAll( Arrays.asList(StringUtils.split( cmd.substring(index, cmd.length()).trim(), " ")));
        }
        if (log.isDebugEnabled()) {
            log.debug("Arguments extracted: " + arguments);
        }
        return arguments;
    }
}
