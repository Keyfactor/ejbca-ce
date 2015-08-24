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

import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CLI subcommand that lists all available services
 * 
 * @version $Id$
 */
public class ServiceListCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(ServiceListCommand.class);

    @Override
    public String[] getCommandPath() {
        return new String[] { "service" };
    }
    
    @Override
    public String getMainCommand() {
        return "list";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        
        final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        Collection<Integer> availableServicesIds = serviceSession.getAuthorizedVisibleServiceIds();
        if (availableServicesIds.size() == 0) {
            getLogger().info("No services are available.");
            return CommandResult.SUCCESS;
        }
        
        getLogger().info("Actv| Service name    | Worker           | Interval         | Action           ");
        getLogger().info("----+-----------------+------------------+------------------+------------------");
        for (Integer serviceId : availableServicesIds) {
            StringBuilder row = new StringBuilder();
            ServiceConfiguration serviceConfig = serviceSession.getServiceConfiguration(serviceId);
            
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
        return CommandResult.SUCCESS;
    }
    
    
    private void addClassPath(StringBuilder row, String classPath) {
        row.append(' ');
        final String className = classPath.replaceFirst("^.*\\.", "");
        row.append(StringUtils.rightPad(StringUtils.abbreviate(className, 16), 17));
    }
    
    @Override
    public String getCommandDescription() {
        return "Lists all available services";
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
