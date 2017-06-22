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
package org.ejbca.ui.cli.config.scep;

import java.util.Enumeration;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * @version $Id$
 *
 */
public class DumpAllConfigCommand extends BaseScepConfigCommand {

    private static final Logger log = Logger.getLogger(DumpAllConfigCommand.class);
    
    @Override
    public String getMainCommand() {
        return "dumpall";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        Properties properties;
        try {
            properties = getGlobalConfigurationSession().getAllProperties(getAuthenticationToken(),
                    ScepConfiguration.SCEP_CONFIGURATION_ID);
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user is not authorized to dump configuration.");
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
        return "Shows all current SCEP configurations.";
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
