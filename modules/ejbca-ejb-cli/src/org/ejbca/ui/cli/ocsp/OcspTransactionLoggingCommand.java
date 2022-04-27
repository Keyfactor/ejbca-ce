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
package org.ejbca.ui.cli.ocsp;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Implements the CLI command <code>./ejbca.sh ocsp transactionlogging</code>.
 */
public class OcspTransactionLoggingCommand extends EjbcaCliUserCommandBase {
    private static final Logger log = Logger.getLogger(OcspTransactionLoggingCommand.class);
    private static final String ENABLE_KEY = "--enable";
    private static final String LOG_PATTERN_KEY = "--log-pattern";
    private static final String LOG_VALUES_KEY = "--log-values";
    private static final String DATE_FORMAT_KEY = "--date-format";
    private static final String PRINT_KEY = "--print";

    {
        registerParameter(new Parameter(ENABLE_KEY,
                "OCSP transaction logging status",
                MandatoryMode.OPTIONAL,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Enable or disable OCSP transaction logging. Set to 'true' to enable OCSP audit logging, or 'false' to disable."));
        registerParameter(new Parameter(LOG_PATTERN_KEY,
                "Variable pattern",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "A pattern used to identify a variable. Use \"\\$\\{(.+?)\\}\" to use variables like ${THIS}."));
        registerParameter((new Parameter(LOG_VALUES_KEY,
                "Log pattern",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "The transaction log message. Variables may be used as specified in the documentation.")));
        registerParameter(new Parameter(DATE_FORMAT_KEY,
                "Date format",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Specify how time should be logged using an RFC 3339 compliant date string, e.g. \"yyyy-MM-dd HH:mm:ss.SSSZ\"."));
        registerParameter(new Parameter(PRINT_KEY,
                "Print",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.FLAG,
                "Print the current configuration."));
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "ocsp" };
    }

    @Override
    public String getMainCommand() {
        return "transactionlogging";
    }

    @Override
    public CommandResult execute(final ParameterContainer parameters) {
        try {
            final GlobalConfigurationSessionRemote globalConfigurationSession =
                    EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
            final GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession
                    .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
            if (parameters.containsKey(ENABLE_KEY)) {
                ocspConfiguration.setIsOcspTransactionLoggingEnabled(Boolean.parseBoolean(parameters.get(ENABLE_KEY)));
            }
            if (parameters.containsKey(LOG_PATTERN_KEY)) {
                ocspConfiguration.setOcspTransactionLogPattern(parameters.get(LOG_PATTERN_KEY));
            }
            if (parameters.containsKey(LOG_VALUES_KEY)) {
                ocspConfiguration.setOcspTransactionLogValues(parameters.get(LOG_VALUES_KEY));
            }
            if (parameters.containsKey(DATE_FORMAT_KEY)) {
                ocspConfiguration.setOcspLoggingDateFormat(parameters.get(DATE_FORMAT_KEY));
            }
            globalConfigurationSession.saveConfiguration(getAuthenticationToken(), ocspConfiguration);
            if (parameters.containsKey(PRINT_KEY)) {
                print((GlobalOcspConfiguration) globalConfigurationSession
                        .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID));
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error(e);
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Configure OCSP transaction logging.";
    }

    @Override
    public String getFullHelpText() {
        return "Configure whether OCSP transaction logging should be enabled and what the audit log messages should look like.";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    private void print(final GlobalOcspConfiguration ocspConfiguration) {
        log.info("enabled: " + ocspConfiguration.getIsOcspTransactionLoggingEnabled());
        log.info("log_pattern: " + ocspConfiguration.getOcspTransactionLogPattern());
        log.info("log_values: " + ocspConfiguration.getOcspTransactionLogValues());
        log.info("date_format: " + ocspConfiguration.getOcspLoggingDateFormat());
    }
}
