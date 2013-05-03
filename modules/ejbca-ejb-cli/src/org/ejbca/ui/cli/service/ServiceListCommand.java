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

import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * CLI subcommand that lists all available services
 * 
 * @version $Id$
 */
public class ServiceListCommand extends BaseServiceCommand {

    @Override
    public String getSubCommand() {
        return "list";
    }

    @Override
    public String getDescription() {
        return "Lists all available servies";
    }

    @Override
    public void execute(String[] args, int unusedParameter) throws ErrorAdminCommandException {
        if (args.length != 1) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand());
            return;
        }
        
        final ServiceSessionRemote serviceSession = ejb.getRemoteSession(ServiceSessionRemote.class);
        Collection<Integer> availableServicesIds = serviceSession.getAuthorizedVisibleServiceIds(getAdmin());
        if (availableServicesIds.size() == 0) {
            getLogger().info("No services are available.");
            return;
        }
        
        getLogger().info("Actv| Service name    | Worker           | Interval         | Action           ");
        getLogger().info("----+-----------------+------------------+------------------+------------------");
        for (Integer serviceId : availableServicesIds) {
            StringBuilder row = new StringBuilder();
            ServiceConfiguration serviceConfig = serviceSession.getServiceConfiguration(getAdmin(), serviceId);
            
            // Active
            row.append(serviceConfig.isActive() ? "  X |" : "    |");
            
            // Name
            row.append(' ');
            String serviceName = serviceSession.getServiceName(serviceId.intValue());
            row.append(StringUtils.rightPad(StringUtils.abbreviate(serviceName, 15), 16));
            row.append('|');
            
            // Class paths
            addClassPath(row, serviceConfig.getWorkerClassPath());
            row.append('|');
            addClassPath(row, serviceConfig.getIntervalClassPath());
            row.append('|');
            addClassPath(row, serviceConfig.getActionClassPath());
            
            getLogger().info(row.toString());
        }
    }
    
    @Override
    protected boolean acceptsServiceName() { return false; }
    
    private void addClassPath(StringBuilder row, String classPath) {
        row.append(' ');
        final String className = classPath.replaceFirst("^.*\\.", "");
        row.append(StringUtils.rightPad(StringUtils.abbreviate(className, 16), 17));
    }

}
