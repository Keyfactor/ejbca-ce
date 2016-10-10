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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CLI subcommand that shows the settings of a service.
 * 
 * @version $Id$
 */
public class ServiceInfoCommand extends BaseServiceCommand {

    private static final Logger log = Logger.getLogger(ServiceInfoCommand.class);

    @Override
    public String getMainCommand() {
        return "info";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters, int serviceId) {
        
        final ServiceSessionRemote serviceSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ServiceSessionRemote.class);
        ServiceConfiguration serviceConfig = serviceSession.getServiceConfiguration(serviceId);
        
        info("Id", serviceId);
        info("Name", serviceSession.getServiceName(serviceId));
        
        getLogger().info("");
        getLogger().info("----- Worker -----");
        info("Worker class", serviceConfig.getWorkerClassPath());
        showProperties(serviceConfig.getWorkerProperties());
        
        getLogger().info("");
        getLogger().info("-----Interval -----");
        info("Interval class", serviceConfig.getIntervalClassPath());
        showProperties(serviceConfig.getIntervalProperties());
        
        getLogger().info("");
        getLogger().info("----- Action -----");
        info("Action class", serviceConfig.getActionClassPath());
        showProperties(serviceConfig.getActionProperties());
        
        getLogger().info("");
        getLogger().info("----- General Settings -----");
        info("Active", serviceConfig.isActive());
        info("Pin to nodes", serviceConfig.getPinToNodes());
        info("Run on all nodes", serviceConfig.isRunOnAllNodes());
        info("Description", serviceConfig.getDescription());
        return CommandResult.SUCCESS;
    }
    
    /** Displays "name: value" with proper alignment */
    private void info(String name, String value) {
        if (value == null) {
            value = "null";
        }
        
        value = value.replaceAll("\r?\n", "\n"+StringUtils.repeat(" ", 15));
        getLogger().info(StringUtils.rightPad(name, 13)+": "+value);
    }
    
    private void info(String name, int value) {
        info(name, String.valueOf(value));
    }
    
    private void info(String name, boolean value) {
        info(name, value ? "Yes" : "No");
    }
    
    private void info(String name, String[] value) {
        if (value == null) {
            info(name, "null");
            return;
        }
        
        info(name, StringUtils.join(value, '\n'));
    }
    
    private void showProperties(Properties props) {
        if (props == null) {
            getLogger().info("Properties object is null.");
            return;
        }
        
        StringBuilder sb = new StringBuilder("Properties:\n");
        for (Entry<Object,Object> entry : props.entrySet()) {
            sb.append("  ");
            sb.append(entry.getKey().toString());
            sb.append(" = ");
            sb.append(entry.getValue().toString());
            sb.append('\n');
        }
        sb.deleteCharAt(sb.length()-1);
        getLogger().info(sb.toString());
    }
    

    @Override
    public String getCommandDescription() {
        return "Show information about a service.";
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
