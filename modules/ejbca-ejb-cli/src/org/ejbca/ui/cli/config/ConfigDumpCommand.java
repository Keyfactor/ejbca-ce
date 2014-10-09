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

package org.ejbca.ui.cli.config;

import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Shows the current server configuration
 * 
 * @version $Id$
 */
public class ConfigDumpCommand extends ConfigBaseCommand {

    private static final Logger log = Logger.getLogger(ConfigDumpCommand.class);

    @Override
    public String getMainCommand() {
        return "dump";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.info("Trying to fetch currently used server properties...");

        Properties properties;
        try {
            properties = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class).getAllProperties(getAuthenticationToken(),
                    GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to retrieve global configuration.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        Enumeration<Object> enumeration = properties.keys();
        while (enumeration.hasMoreElements()) {
            String key = (String) enumeration.nextElement();
            log.info(" " + key + " = " + properties.getProperty(key));
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Shows the current server configuration";
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
