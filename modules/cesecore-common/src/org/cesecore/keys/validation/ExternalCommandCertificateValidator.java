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
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.profiles.Profile;
import org.cesecore.util.CertTools;
import org.cesecore.util.ExternalProcessException;
import org.cesecore.util.ExternalProcessTools;
import org.cesecore.util.ui.DynamicUiActionCallback;
import org.cesecore.util.ui.DynamicUiCallbackException;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;

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

    static {
        APPLICABLE_CA_TYPES.add(CAInfo.CATYPE_X509);
    }

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
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data);
        uiModel.add(new DynamicUiProperty<String>("settings"));
        final DynamicUiProperty<String> cmd = new DynamicUiProperty<String>(String.class, EXTERNAL_COMMAND, getExternalCommand());
        cmd.setRequired(true);
        uiModel.add(cmd);
        uiModel.add(new DynamicUiProperty<Boolean>(Boolean.class, FAIL_ON_ERROR_CODE, isFailOnErrorCode()));
        uiModel.add(new DynamicUiProperty<Boolean>(Boolean.class, FAIL_ON_STANDARD_ERROR, isFailOnStandardError()));
        uiModel.add(new DynamicUiProperty<Boolean>(Boolean.class, LOG_STANDARD_OUT, isLogStandardOut()));
        uiModel.add(new DynamicUiProperty<Boolean>(Boolean.class, LOG_ERROR_OUT, isLogErrorOut()));
        uiModel.add(new DynamicUiProperty<String>("test"));
        final DynamicUiProperty<File> testPath = new DynamicUiProperty<File>(File.class, "testPath", null);
        testPath.setTransientValue(true);
        uiModel.add(testPath);
        // ECA-6320 Bug. MyFaces HtmlOutputText and HtmlOutputLabel throw NPE in JSF life cycle -> use disabled text field.
//        final DynamicUiProperty<String> testOut = new DynamicUiProperty<String>("testOut");
//        testOut.setLabelOnly(false);
//        testOut.setRenderingHint(DynamicUiProperty.RENDER_LABEL);
//        uiModel.add(testOut);
        final DynamicUiProperty<String> testOut = new DynamicUiProperty<String>("testOut");
        testOut.setLabelOnly(false);
        testOut.setRenderingHint(DynamicUiProperty.RENDER_TEXTFIELD);
        testOut.setDisabled(true);
        final DynamicUiProperty<String> testButton = new DynamicUiProperty<String>(String.class, "testCommand", "testCommand");
        testButton.setRenderingHint(DynamicUiProperty.RENDER_BUTTON);
        testButton.setActionCallback(new DynamicUiActionCallback() {
            @Override
            @SuppressWarnings("unchecked")
            public void action(final Object parameter) throws DynamicUiCallbackException {
                final List<String> out = testCommand();
                final Map<Object, Object> oldValues = (Map<Object, Object>) data.clone();
                final Map<Object, Object> newValues = (Map<Object, Object>) data.clone();
                newValues.put("testOut", StringUtils.join(out, System.getProperty("line.separator")));
                newValues.put("testPath", "");
                uiModel.firePropertyChange(oldValues, newValues);
                setTestCertificates(ListUtils.EMPTY_LIST);
            }
            @Override
            public List<String> getRender() {
                return null;
            }
        });
        uiModel.add(testButton);
        uiModel.add(testOut);
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
        if (log.isDebugEnabled()) {
            log.debug("Validating certificate with external command: " + getExternalCommand());
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
            throw new ValidatorNotApplicableException( "External command could not be called, because it does not exit, command can not be found, access was denied, certificate not written, or another error occured: "+e.getMessage());
        }
        // Validator was applicable but something bad must have happened, no exit code was returned -> validation failed.
        boolean broken = false;
        if (CollectionUtils.isNotEmpty(out)) {
            try {
                if (isLogStandardOut()) {
                    String stdOutput = null;
                    for (String str : out) {
                        if (str.startsWith(ExternalProcessTools.STDOUT_PREFIX)) {
                            if (stdOutput == null) {
                                stdOutput = str;
                            } else {
                                stdOutput += "\n" + str;
                            }
                        }
                    }
                    if (stdOutput != null) {
                        log.info("External command logged to STDOUT: "+stdOutput);
                    }
                }
                String errOutput = null;
                if (isLogErrorOut()) {
                    for (String str : out) {
                        if (str.startsWith(ExternalProcessTools.ERROUT_PREFIX)) {
                            if (errOutput == null) {
                                errOutput = str;
                            } else {
                                errOutput += "\n" + str;
                            }
                        }
                    }
                    if (errOutput != null) {
                        log.info("External command logged to ERROUT: "+errOutput);
                    }
                }
                final int exitCode = Integer.parseInt(out.get(0).replaceFirst(ExternalProcessTools.EXIT_CODE_PREFIX, StringUtils.EMPTY));
                if (exitCode != 0 && isFailOnErrorCode()) { // Validation failed: -1 is command could not be found or access denied.
                    messages.add("Invalid: External command exit code was " + exitCode);
                    if (errOutput != null) {
                        messages.add("ERROUT was: " + errOutput);
                    }
                } else if (isFailOnStandardError() && ExternalProcessTools.containsErrout(out)) {
                    messages.add("Invalid: External command logged to ERROUT. Exit code was " + exitCode);
                    if (errOutput != null) {
                        messages.add("ERROUT was: " + errOutput);
                    }
                }
            } catch(Exception e2) { // In case exit code could not be parsed.
                broken = true;
            }
        } else {
            broken = true;
        }
        if (broken) {
            messages.add("Invalid: External command could not be initialized: '" + cmd + "'. Command failed.");
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

    /**
     * Sets the external script path.
     * @param path the path.
     */
    public void setExternalCommand(final String path) {
        data.put(EXTERNAL_COMMAND, path);
    }

    /**
     * Gets the external script path
     * @return the path.
     */
    public String getExternalCommand() {
        return (String) data.get(EXTERNAL_COMMAND);
    }

    /**
     * Denotes if the STDOUT of the external command or script has to be logged.
     * @param state true if enabled.
     */
    public void setLogStandardOut(final boolean state) {
        data.put(LOG_STANDARD_OUT, Boolean.valueOf(state));
    }

    /**
     * Denotes if the STDOUT of the external command or script has to be logged.
     * @return true if enabled.
     */
    public boolean isLogStandardOut() {
        return ((Boolean) data.get(LOG_STANDARD_OUT)).booleanValue();
    }

    /**
     * Denotes if the ERROUT of the external command or script has to be logged.
     * @param state true if enabled.
     */
    public void setLogErrorOut(final boolean state) {
        data.put(LOG_ERROR_OUT, Boolean.valueOf(state));
    }

    /**
     * Denotes if the ERROUT of the external command or script has to be logged.
     * @return true if enabled.
     */
    public boolean isLogErrorOut() {
        return ((Boolean) data.get(LOG_ERROR_OUT)).booleanValue();
    }

    /**
     * Denotes if the command or script has to be considered as failed if the exit code is larger than 0.
     * @param state true if enabled.
     */
    public void setFailOnErrorCode(final boolean state) {
        data.put(FAIL_ON_ERROR_CODE, Boolean.valueOf(state));
    }

    /**
     * Denotes if the command or script has to be considered as failed if the exit code is larger than 0.
     * @return true if enabled.
     */
    public boolean isFailOnErrorCode() {
        return ((Boolean) data.get(FAIL_ON_ERROR_CODE)).booleanValue();
    }

    /**
     * Denotes if the command or script has to be considered as failed if a log was written to ERROUT.
     * @param state true if enabled.
     */
    public void setFailOnStandardError(final boolean state) {
        data.put(FAIL_ON_STANDARD_ERROR, Boolean.valueOf(state));
    }

    /**
     * Denotes if the command or script has to be considered as failed if a log was written to ERROUT
     * @return true if enabled.
     */
    public boolean isFailOnStandardError() {
        return ((Boolean) data.get(FAIL_ON_STANDARD_ERROR)).booleanValue();
    }

    /**
     * Tests the external command with the uploaded test certificate.
     * @return a list with size > 0 and the exit code in field with index 0 and STDOUT and ERROR appended subsequently.
     * @throws DynamicUiCallbackException if the external script path does not exist or accessible or the script call fails otherwise.
     */
    @SuppressWarnings("unchecked")
    public List<String> testCommand() throws DynamicUiCallbackException {
        log.info("Test external command certificate validator " + getProfileName());
        final DynamicUiProperty<File> property = (DynamicUiProperty<File>) uiModel.getProperties().get("testPath");
        final List<String> out = new ArrayList<String>();
        File file = null;
        String message = null;
        if (property != null && (file=property.getValue()) != null && file.exists()) {
            if (!file.canRead()) {
                message = intres.getLocalizedMessage("validator.certificate.externalcommand.testfilenopermission", file.getAbsolutePath());
            }
            if (message == null) {
                try {
                    setTestCertificates(CertTools.getCertsFromPEM(file.getAbsolutePath(), Certificate.class));
                } catch(IOException e) {
                    message = intres.getLocalizedMessage("process.certificate.filenotfound", file.getAbsolutePath());
                    log.warn(message, e);
                } catch(CertificateParsingException e) {
                    message = intres.getLocalizedMessage("process.certificate.couldnotbeparsed", file.getAbsolutePath());
                    log.warn(message, e);
                }
            }
            if (message == null) { // Run command.
                try {
                    out.addAll(runExternalCommandInternal(getExternalCommand(), ExternalScriptsWhitelist.permitAll(), getTestCertificates()));
                    if (log.isDebugEnabled()) {
                        log.debug("Tested certificate with external command STOUT/ERROUT:" + System.getProperty("line.separator") + out);
                    }
                } catch (CertificateEncodingException e) {
                    message = intres.getLocalizedMessage("process.certificate.couldnotbeencoded", file.getAbsolutePath());
                    log.info(message, e);
                // 1. command not found, no permission or other exception; 2. not in whitelist.
                } catch (ExternalProcessException | ValidatorNotApplicableException e) {
                    message = e.getMessage();
                    log.info(message, e);
                }
            }
        } else {
            message = intres.getLocalizedMessage("validator.certificate.externalcommand.testfilemissing", getExternalCommand());
            log.info(message);
        }
        // Delete temporary file (file is written because of file upload).
        if (file != null && file.exists()) {
            try {
                file.delete();
            } catch(Exception | Error e) {
                log.trace("Could not delete temporary file: " + file.getAbsolutePath(), e);
            }
        }
        if (StringUtils.isNotBlank(message)) {
            throw new DynamicUiCallbackException(message);
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

    /**
     * Sets the list of test certificates uploaded by the user.
     * @param testCertificates the list.
     */
    public void setTestCertificates(final List<Certificate> testCertificates) {
        this.testCertificates = testCertificates;
        if (log.isDebugEnabled()) {
            log.debug("Test certificates uploaded: " + testCertificates);
        }
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
     * @throws ExternalProcessException if the command wasn't found
     * @throws ValidatorNotApplicableException if external scripts whitelist wasn't permitted
     */
    private List<String> runExternalCommandInternal(final String externalCommand, final ExternalScriptsWhitelist externalScriptsWhitelist,
            final List<Certificate> certificates) throws CertificateEncodingException, ExternalProcessException, ValidatorNotApplicableException {
        final String cmd = extractCommand(externalCommand);
        if (!externalScriptsWhitelist.isPermitted(cmd)) {
             throw new ValidatorNotApplicableException(intres.getLocalizedMessage("process.whitelist.error.notlisted", cmd));
        }
        // Test if specified script file exists and is executable (hits files and symbolic links, but no aliases).
        if (StringUtils.isNotBlank(cmd)) {
            final File file = new File(cmd);
            String message;
            if (!file.exists()) {
                message = intres.getLocalizedMessage("process.commandnotfound", cmd);
                log.info(message);
                throw new ExternalProcessException(message);
            }
            if (!file.canExecute()) {
                message = intres.getLocalizedMessage("process.commandnopermission", cmd);
                log.info(message);
                throw new ExternalProcessException(message);
            }
        }
        // Extract arguments and run external script.
        final List<String> arguments = extractArguments(externalCommand);
        final List<String> out = new ArrayList<String>();
        try {
            out.addAll(ExternalProcessTools.launchExternalCommand(cmd, certificates.get(0).getEncoded(),
                    isFailOnErrorCode(), isFailOnStandardError(), isLogStandardOut(), isLogErrorOut(), arguments, this.getClass().getName()));
        } catch (ExternalProcessException e) {
            log.info("Could not call external command '" + cmd + "' with arguments " + arguments + " sucessfully: " + e.getMessage());
            if (log.isDebugEnabled()) {
                log.debug("Failed with exception: ", e);
            }
            if (e.getOut() != null) {
                out.addAll(e.getOut());
            }
        }
        return out;
    }

    /**
     * Extracts the script path.
     *
     * @param cmd the external command.
     * @return the script path (first token in command).
     */
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

    /**
     * Extracts the arguments.
     *
     * @param cmd the external command.
     * @return the list of arguments (second token to end).
     */
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
