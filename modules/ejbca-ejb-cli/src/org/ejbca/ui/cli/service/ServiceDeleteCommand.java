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
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * CLI subcommand for deleting services.
 * 
 * @version $Id$
 */
public class ServiceDeleteCommand extends BaseServiceCommand {

    @Override
    public String getSubCommand() {
        return "delete";
    }

    @Override
    public String getDescription() {
        return "Deletes a service.";
    }

    @Override
    public void execute(String[] args, int serviceId) throws ErrorAdminCommandException {
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <service name>");
            return;
        }
        
        final ServiceSessionRemote serviceSession = ejb.getRemoteSession(ServiceSessionRemote.class);
        final String serviceName = serviceSession.getServiceName(serviceId);
        if (serviceSession.removeService(getAdmin(), serviceName)) {
            getLogger().info("Service deleted.");
        } else {
            getLogger().info("Failed to delete service: "+serviceName);
        }
    }
}
