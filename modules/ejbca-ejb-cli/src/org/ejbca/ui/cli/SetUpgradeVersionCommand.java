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

package org.ejbca.ui.cli;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.config.GlobalUpgradeConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Sets the initial/deployed/post-upgrade version number in the database.
 * For testing and troubleshooting usage.
 */
public class SetUpgradeVersionCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(SetUpgradeVersionCommand.class);

    private static final String INITIAL_VERSION_KEY = "--initial";
    private static final String DEPLOYED_VERSION_KEY = "--deployed";
    private static final String POSTUPGRADED_VERSION_KEY = "--post-upgraded";

    private static final String INITIAL_NOTE = "note that versions before 5.0 did not store the initial version";

    {
        registerParameter(new Parameter(INITIAL_VERSION_KEY, "Initial version", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Sets the version number of the initial installation."));
        registerParameter(new Parameter(DEPLOYED_VERSION_KEY, "Deployed version", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Sets the currently deployed version number."));
        registerParameter(new Parameter(POSTUPGRADED_VERSION_KEY, "Post-upgraded version", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "Sets the currently post-upgraded version number."));
    }

    @Override
    public String getMainCommand() {
        return "setupgradeversion";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        final GlobalUpgradeConfiguration upgradeConfig = (GlobalUpgradeConfiguration) globalConfigSession.getCachedConfiguration(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        if (!parameters.containsKey(INITIAL_VERSION_KEY) && !parameters.containsKey(DEPLOYED_VERSION_KEY) && !parameters.containsKey(POSTUPGRADED_VERSION_KEY)) {
            printManPage();
            log.info("Current versions in database:");
            log.info("Initial installation version: " + upgradeConfig.getUpgradedFromVersion() + " *");
            log.info("Highest deployed version:     " + upgradeConfig.getUpgradedToVersion());
            log.info("Post-upgraded to version:     " + upgradeConfig.getPostUpgradedToVersion());
            log.info("* " + INITIAL_NOTE);
            return CommandResult.SUCCESS;
        }
        if (parameters.containsKey(INITIAL_VERSION_KEY)) {
            log.info("Setting initial install version to " + StringUtils.rightPad(parameters.get(INITIAL_VERSION_KEY), 14) + " (was " + upgradeConfig.getUpgradedFromVersion() + ", " + INITIAL_NOTE + ")");
            upgradeConfig.setUpgradedFromVersion(parameters.get(INITIAL_VERSION_KEY));
        }
        if (parameters.containsKey(DEPLOYED_VERSION_KEY)) {
            log.info("Setting deployed version to " + StringUtils.rightPad(parameters.get(DEPLOYED_VERSION_KEY), 14+7) + " (was " + upgradeConfig.getUpgradedToVersion() + ")");
            upgradeConfig.setUpgradedToVersion(parameters.get(DEPLOYED_VERSION_KEY));
        }
        if (parameters.containsKey(POSTUPGRADED_VERSION_KEY)) {
            log.info("Setting post-upgraded version to " + StringUtils.rightPad(parameters.get(POSTUPGRADED_VERSION_KEY), 14+2) + " (was " + upgradeConfig.getPostUpgradedToVersion() + ")");
            upgradeConfig.setPostUpgradedToVersion(parameters.get(POSTUPGRADED_VERSION_KEY));
        }
        try {
            globalConfigSession.saveConfiguration(getAuthenticationToken(), upgradeConfig);
        } catch (AuthorizationDeniedException e) {
            log.error("Not authorized to modify configuration: " + e.getMessage());
            log.trace("Stack trace", e);
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        log.info("Saved configuration");
        globalConfigSession.flushConfigurationCache(GlobalUpgradeConfiguration.CONFIGURATION_ID);
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Sets the 'upgrade' and 'post upgrade' versions in database. Internal command; not meant to be used in production.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
