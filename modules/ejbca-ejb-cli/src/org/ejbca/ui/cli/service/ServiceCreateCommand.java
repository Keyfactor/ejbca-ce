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
import org.ejbca.core.model.services.ServiceExistsException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * CLI subcommand for creating services.
 * 
 * @version $Id$
 */
public class ServiceCreateCommand extends BaseServiceModificationCommand {

    @Override
    public String getSubCommand() {
        return "create";
    }

    @Override
    public String getDescription() {
        return "Creates a new service.";
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
            getLogger().info("        service create WeeklyService intervalClassPath=org.ejbca.core.model.services.intervals.PeriodicalInterval interval.periodical.unit=DAYS interval.periodical.value=7");
            return;
        }
        
        final ServiceSessionRemote serviceSession = ejb.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = args[1].trim();
        
        ServiceConfiguration serviceConfig = new ServiceConfiguration();
        if (modifyFromArgs(serviceConfig, args)) {
            try {
                serviceSession.addService(getAdmin(), serviceName, serviceConfig);
                getLogger().info("Service created.");
            } catch (ServiceExistsException e) {
                getLogger().info("Service exists already.");
            }
        }
    }
    
    @Override
    protected boolean failIfServiceMissing() { return false; }
}
