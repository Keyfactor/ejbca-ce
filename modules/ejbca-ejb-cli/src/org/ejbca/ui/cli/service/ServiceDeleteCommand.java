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
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CLI subcommand for deleting services.
 * 
 * @version $Id$
 */
public class ServiceDeleteCommand extends BaseServiceCommand {

    private static final Logger log = Logger.getLogger(ServiceDeleteCommand.class);

    @Override
    public String getMainCommand() {
        return "delete";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {
        final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = serviceSession.getServiceName(serviceId);
        if (serviceSession.removeService(getAdmin(), serviceName)) {
            getLogger().info("Service deleted.");
            return CommandResult.SUCCESS;
        } else {
            getLogger().info("Failed to delete service: " + serviceName);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Deletes a service.";
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
