/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * CLI subcommand for editing services.
 * 
 * @version $Id$
 */
public class ServiceEditCommand extends BaseServiceModificationCommand {

    @Override
    public String getSubCommand() {
        return "edit";
    }

    @Override
    public String getDescription() {
        return "Modifies fields and properties in a service.";
    }

    @Override
    public void execute(String[] args, int serviceId) throws ErrorAdminCommandException {
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <service name> <field or property>=<value>...");
            getLogger().info("   or: " + getCommand() + " <service name> -listFields|-listProperties");
            getLogger().info("");
            displayListFieldsHelp();
            getLogger().info("Example usage:");
            getLogger().info("        service edit TheService1 intervalClassPath=org.ejbca.core.model.services.intervals.PeriodicalInterval interval.periodical.unit=DAYS interval.periodical.value=7");
            getLogger().info("        service edit TheService1 pinToNodes=node1.example.com,node2.example.com active=true");
            return;
        }
        
        final ServiceSessionRemote serviceSession = ejb.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = serviceSession.getServiceName(serviceId);
        ServiceConfiguration serviceConfig = serviceSession.getServiceConfiguration(getAdmin(), serviceId);
        
        if (!argListHasProperties(args)) {
            getLogger().info("Nothing to change.");
        } else if (modifyFromArgs(serviceConfig, args)) {
            serviceSession.changeService(getAdmin(), serviceName, serviceConfig, false);
            getLogger().info("Changes saved.");
        }
    }
}
