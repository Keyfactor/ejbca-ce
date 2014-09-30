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
package org.ejbca.ui.cli.service;

import java.util.Map.Entry;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CLI subcommand that lists all available fields
 * 
 * @version $Id$
 */
public class ServiceListPropertiesCommand extends BaseServiceCommand {

    private static final Logger log = Logger.getLogger(ServiceListPropertiesCommand.class);

    @Override
    public String getMainCommand() {
        return "listproperties";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {
        ServiceConfiguration serviceConfig = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class).getServiceConfiguration(
                getAdmin(), serviceId);
        boolean displayedOne = false;
        displayedOne |= displayPropertiesHelp(serviceConfig.getWorkerProperties());
        displayedOne |= displayPropertiesHelp(serviceConfig.getIntervalProperties());
        displayedOne |= displayPropertiesHelp(serviceConfig.getActionProperties());
        if (!displayedOne) {
            // No properties
            getLogger().info("No properties have been set.");
        }
        return CommandResult.SUCCESS;

    }

    /**
     * Displays all properties and their values. Used for the -listProperties option. 
     * @return true if at least one property was shown
     */
    private boolean displayPropertiesHelp(Properties props) {
        boolean displayedOne = false;
        for (Entry<Object, Object> prop : props.entrySet()) {
            // We don't know the types but we can display the default values so the user can figure out.
            getLogger().info(prop.getKey() + " (current value = '" + prop.getValue() + "')");
            displayedOne = true;
        }
        return displayedOne;
    }

    @Override
    public String getCommandDescription() {
        return "Lists all available properties for a service.";
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
