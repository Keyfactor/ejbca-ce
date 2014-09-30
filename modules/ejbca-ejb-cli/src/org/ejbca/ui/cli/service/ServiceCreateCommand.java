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
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * CLI subcommand for creating services.
 * 
 * @version $Id$
 */
public class ServiceCreateCommand extends BaseServiceModificationCommand {

    private static final Logger log = Logger.getLogger(ServiceCreateCommand.class);

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
        return "create";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {

        final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = parameters.get(SERVICE_NAME_KEY);

        ServiceConfiguration serviceConfig = new ServiceConfiguration();
        final boolean wasActive = false;
        final String[] args;
        if (parameters.containsKey(ARGS_KEY)) {
            args = parameters.get(ARGS_KEY).split(" ");
        } else {
            args = new String[] {};
        }

        if (modifyFromArgs(serviceConfig, args)) {
            try {
                serviceSession.addService(getAdmin(), serviceName, serviceConfig);
                handleServiceActivation(serviceName, wasActive);
                getLogger().info("Service created.");
                return CommandResult.SUCCESS;
            } catch (ServiceExistsException e) {
                getLogger().error("ERROR: Service exists already.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    protected boolean failIfServiceMissing() {
        return false;
    }

    @Override
    public String getCommandDescription() {
        return "Creates a new service.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append("This example creates a service that updates the CRL on a daily basis. "
                + "The worker.caidstocheck value of 1 means check all CAs. "
                + "You can create services from the Admin Web and use the \"service info\" command "
                + "to learn how the CLI fields correspond to the fields in the Admin Web.\n\n");
        sb.append("Example usage: service create DailyCRLUpdate workerClassPath=org.ejbca.core.model.services.workers.CRLUpdateWorker"
                + " worker.caidstocheck=1 intervalClassPath=org.ejbca.core.model.services.intervals.PeriodicalInterval interval.periodical.unit=DAYS"
                + " interval.periodical.value=1 actionClassPath=org.ejbca.core.model.services.actions.NoAction active=true");
        sb.append("\n\n").append(FIELDS_HELP + "\n\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
