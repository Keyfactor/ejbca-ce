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

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.cli.roles.ListRolesCommand;

/**
 * CLI subcommand for editing services.
 * 
 * @version $Id$
 */
public class ServiceEditCommand extends BaseServiceModificationCommand {

    private static final Logger log = Logger.getLogger(ListRolesCommand.class);

    private static final String ARGS_KEY = "--properties";

    {
        registerParameter(new Parameter(
                ARGS_KEY,
                "List of Properties",
                MandatoryMode.OPTIONAL,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "A list of properties, must be in the form of \"field1:property1 field2:property2\", e.g: \"interval.periodical.unit=DAYS interval.periodical.value=7\""));
    }

    @Override
    public String getMainCommand() {
        return "edit";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {
        final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = serviceSession.getServiceName(serviceId);
        ServiceConfiguration serviceConfig = serviceSession.getServiceConfiguration(serviceId);
        final boolean wasActive = serviceConfig.isActive();
        final String[] args;
        if (parameters.get(ARGS_KEY) != null) {
            args = parameters.get(ARGS_KEY).split(" ");
        } else {
            args = new String[] {};
        }
        if (modifyFromArgs(serviceConfig, args)) {
            serviceSession.changeService(getAdmin(), serviceName, serviceConfig, false);
            handleServiceActivation(serviceName, wasActive);
            getLogger().info("Changes saved.");
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Modifies fields and properties in a service.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription());
        sb.append("\n\n").append(FIELDS_HELP + "\n\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
