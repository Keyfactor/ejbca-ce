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
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * @version $Id$
 *
 */
public class DumpAliasCommand extends BaseScepConfigCommand {

    private static final String ALIAS_KEY = "--alias";

    private static final Logger log = Logger.getLogger(DumpAliasCommand.class);

    {
        registerParameter(new Parameter(ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias to dump"));
    }

    @Override
    public String getMainCommand() {
        return "dumpalias";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String alias = parameters.get(ALIAS_KEY);
        Properties properties = getScepConfiguration().getAsProperties(alias);
        if (properties != null) {
            Enumeration<Object> enumeration = properties.keys();
            while (enumeration.hasMoreElements()) {
                String key = (String) enumeration.nextElement();
                log.info(" " + key + " = " + properties.getProperty(key));
            }
            return CommandResult.SUCCESS;
        } else {
            log.error("ERROR: Could not find alias: " + alias);
            return CommandResult.FUNCTIONAL_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Shows the current SCEP configuration for one alias";
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
