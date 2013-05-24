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

    /**
     * Modifies the fields in the given ServiceConfiguration from
     * command-line arguments. The syntax is:
     * 
     *  servicename [-listFields|-listProperties] fieldOrProperty=value...
     * 
     * This method handles the -list arguments as well, which show which fields
     * and properties can be set.
     */
    protected boolean modifyFromArgs(ServiceConfiguration serviceConfig, String[] args) {
        FieldEditor fieldEditor = new FieldEditor(getLogger());

        // Parse fields to modify
        List<String> params = Arrays.asList(args).subList(2, args.length);
        List<String> notfound = new ArrayList<String>();
        for (String property : params) {
            String[] arr = property.split("=", 2);
            String field = arr[0].trim();
            String value = arr[1].trim();
            if (!modify(serviceConfig, fieldEditor, field, value)) {
                notfound.add(field);
            }
        }
        
        if (!notfound.isEmpty()) {
            displayNotFound(notfound);
            return false;
        }
        
        return true;
    }

    /**
     * Modifies a given field or property in a ServiceConfiguration, using the a FieldEditor.
     * 
     * First it tries to find a field with the given name, then it tries with the
     * worker/interval/action properties.
     */
    private boolean modify(ServiceConfiguration serviceConfig, FieldEditor fieldEditor, String field, String value) {
        boolean found = false;
        try {
            // Try to call the setter 
            fieldEditor.listGetOrSet(false, false, ServiceConfiguration.class.getName(), field, value, serviceConfig);
            getLogger().info("Updated field: "+field);
            getLogger().info("New field value: "+fieldEditor.getBeanValue(field, serviceConfig));
            found = true;
        } catch (ErrorAdminCommandException e) {
            // Check if it's in one of the Properties objects
            Properties props;
            
            props = serviceConfig.getWorkerProperties();
            if (props.containsKey(field) || field.startsWith("worker.")) {
                props.setProperty(field, value);
                getLogger().info("Updated worker property: "+field);
                serviceConfig.setWorkerProperties(props);
                getLogger().info("New worker property value: "+serviceConfig.getWorkerProperties().getProperty(field));
                found = true;
            }
            
            props = serviceConfig.getIntervalProperties();
            if (props.containsKey(field) || field.startsWith("interval.")) {
                props.setProperty(field, value);
                getLogger().info("Updated interval property: "+field);
                serviceConfig.setIntervalProperties(props);
                getLogger().info("New interval property value: "+serviceConfig.getIntervalProperties().getProperty(field));
                found = true;
            }
            
            props = serviceConfig.getActionProperties();
            if (props.containsKey(field) || field.startsWith("action.")) {
                props.setProperty(field, value);
                getLogger().info("Updated action property: "+field);
                serviceConfig.setActionProperties(props);
                getLogger().info("New action property value: "+serviceConfig.getActionProperties().getProperty(field));
                found = true;
            }
            
            if (!found) {
                getLogger().info(e.getMessage());
            }
        }
        return found;
    }
    
    /** Checks if the given argument list has any property assignments */
    protected boolean argListHasProperties(String[] args) {
        return !Arrays.asList(args).contains("-listFields") && 
            !Arrays.asList(args).contains("-listProperties") &&
            args.length >= 3; // "edit NameOfService property..."
    }
    
    /** Handles the -listFields and -listProperties options. */
    protected boolean handleListOptions(ServiceConfiguration serviceConfig, String[] args) {
        final FieldEditor fieldEditor = new FieldEditor(getLogger());
        boolean hasOption = false;
        if (Arrays.asList(args).contains("-listFields")) { 
            fieldEditor.listSetMethods(serviceConfig);
            hasOption = true;
        }
        if (Arrays.asList(args).contains("-listProperties")) {
            boolean displayedOne = false;
            displayedOne |= displayPropertiesHelp(serviceConfig.getWorkerProperties());
            displayedOne |= displayPropertiesHelp(serviceConfig.getIntervalProperties());
            displayedOne |= displayPropertiesHelp(serviceConfig.getActionProperties());
            if (!displayedOne) {
                // No properties
                getLogger().info("create".equals(args[0]) ?
                    "The -listProperties option can presently only be used with the edit command." :
                    "No properties have been set.");
            }
            hasOption = true;
        }
        return hasOption;
    }
    
    /**
     * Displays all properties and their values. Used for the -listProperties option. 
     * @return true if at least one property was shown
     */
    private boolean displayPropertiesHelp(Properties props) {
        boolean displayedOne = false;
        for (Entry<Object,Object> prop : props.entrySet()) {
            // We don't know the types but we can display the default values so the user can figure out.
            getLogger().info(prop.getKey()+" (current value = '"+prop.getValue()+"')");
            displayedOne = true;
        }
        return displayedOne;
    }
    
    /** Displays names of fields/properties that weren't found. */
    private void displayNotFound(List<String> errors) {
        getLogger().info("");
        getLogger().info("ERROR: One or more names didn't exist either as a field or property:");
        getLogger().info("");
        for (String error : errors) {
            getLogger().info("    "+error);
        }
        getLogger().info("");
        getLogger().info("Changes were NOT saved!");
    }
    
    /** Displays the help text about -listFields and -listProperties accepted by the "create" and "edit" commands. */
    protected void displayListFieldsHelp() {
        getLogger().info("Use the -listFields and -listProperties options to see which fields and");
        getLogger().info("properties exist. The \"fields\" are related directly to the");
        getLogger().info("service, e.g. it's description and whether it's active. The properties");
        getLogger().info("are used by the different worker/interval/action classes.");
        getLogger().info("");
        getLogger().info("Note that no properties are set by default with the \"create\" command.");
        getLogger().info("You must either use the Admin Web when creating the service or know in");
        getLogger().info("advance which properties are required. It is NOT possible to list");
        getLogger().info("non-existent (but required) properties from the CLI.");
        getLogger().info("");
    }

}
