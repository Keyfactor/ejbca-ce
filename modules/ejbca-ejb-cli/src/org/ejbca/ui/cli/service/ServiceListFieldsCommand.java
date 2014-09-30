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
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CLI subcommand that lists all available fields
 * 
 * @version $Id$
 */
public class ServiceListFieldsCommand extends BaseServiceCommand {

    private static final Logger log = Logger.getLogger(ServiceListFieldsCommand.class);

    @Override
    public String getMainCommand() {
        return "listfields";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {
        ServiceConfiguration serviceConfig = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class).getServiceConfiguration(
                getAdmin(), serviceId);
        final FieldEditor fieldEditor = new FieldEditor(log);
        fieldEditor.listSetMethods(serviceConfig);
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Lists all available fields for a service";
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
