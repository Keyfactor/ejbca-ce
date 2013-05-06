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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.FieldEditor;

/**
 * Base class with methods to modify beans dynamically using FieldEditor.
 * 
 * @version $Id$
 */
public abstract class BaseServiceModificationCommand extends BaseServiceCommand {

    protected boolean modifyFromArgs(ServiceConfiguration serviceConfig, String[] args) {
        FieldEditor fieldEditor = new FieldEditor(getLogger());
        
        // Check help arguments
        boolean exit = false;
        if (Arrays.asList(args).contains("-listFields")) { 
            fieldEditor.listSetMethods(serviceConfig);
            exit = true;
        }
        if (Arrays.asList(args).contains("-listProperties")) {
            displayPropertiesHelp(serviceConfig.getWorkerProperties());
            displayPropertiesHelp(serviceConfig.getIntervalProperties());
            displayPropertiesHelp(serviceConfig.getActionProperties());
            exit = true;
        }
        if (exit) return false;
        
        
        // Parse fields to modify
        List<String> params = Arrays.asList(args).subList(2, args.length);
        List<String> errors = new ArrayList<String>();
        for (String property : params) {
            if (property.equals("-listFields")) continue;
            String[] arr = property.split("=", 2);
            String field = arr[0].trim();
            String value = arr[1].trim();
            if (!modify(serviceConfig, fieldEditor, field, value)) {
                errors.add(field);
            }
        }
        
        if (!errors.isEmpty()) {
            getLogger().info("");
            getLogger().info("ERROR: One or more names didn't exist either as a field or property:");
            getLogger().info("");
            for (String error : errors) {
                getLogger().info("    "+error);
            }
            getLogger().info("");
            getLogger().info("Changes were NOT saved!");
            return false;
        }
        
        return true;
    }

    private boolean modify(ServiceConfiguration serviceConfig, FieldEditor fieldEditor, String field, String value) {
        try {
            // Try to call the setter 
            fieldEditor.listGetOrSet(false, false, ServiceConfiguration.class.getName(), field, value, serviceConfig);
            getLogger().info("Updated field: "+field);
            return true;
        } catch (ErrorAdminCommandException e) {
            // Check if it's in one of the Properties objects
            Properties props;
            
            props = serviceConfig.getWorkerProperties();
            if (props.containsKey(field) || field.startsWith("worker.")) {
                props.setProperty(field, value);
                getLogger().info("Updated worker property: "+field);
                serviceConfig.setWorkerProperties(props);
                return true;
            }
            
            props = serviceConfig.getIntervalProperties();
            if (props.containsKey(field) || field.startsWith("interval.")) {
                props.setProperty(field, value);
                getLogger().info("Updated interval property: "+field);
                serviceConfig.setIntervalProperties(props);
                return true;
            }
            
            props = serviceConfig.getActionProperties();
            if (props.containsKey(field) || field.startsWith("action.")) {
                props.setProperty(field, value);
                getLogger().info("Updated action property: "+field);
                serviceConfig.setActionProperties(props);
                return true;
            }
            
            getLogger().info(e.getMessage());
            return false;
        }
    }
        
    private void displayPropertiesHelp(Properties props) {
        for (Entry<Object,Object> prop : props.entrySet()) {
            // We don't know the types but we can display the default values so the user can figure out.
            getLogger().info(prop.getKey()+" (current value = "+prop.getValue()+")");
        }
    }

}
