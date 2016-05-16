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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.FieldNotFoundException;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Base class with methods to modify beans dynamically using FieldEditor.
 * 
 * @version $Id$
 */
public abstract class BaseServiceModificationCommand extends BaseServiceCommand {

    /** Displays the help text about -listFields and -listProperties accepted by the "create" and "edit" commands. */
    protected final String FIELDS_HELP = "The \"fields\" are related directly to the "
            + "service, e.g. it's description and whether it's active. The properties are used by the different worker/interval/action classes.\n" +
            "Note that no properties are set by default with the \"create\" command. "
            + "You must either use the Admin Web when creating the service or know in "
            + "advance which properties are required. It is NOT possible to list " + "non-existent (but required) properties from the CLI.";
    
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
        boolean success = true;

        // Parse fields to modify
        List<String> params = Arrays.asList(args);
        List<String> notfound = new ArrayList<String>();
        for (String property : params) {
            String[] arr = property.split("=", 2);
            if (arr.length != 2) {
                getLogger().info("ERROR: Property is missing a value (the syntax is property=value):  " + arr[0]);
                success = false;
                continue;
            }
            String field = arr[0].trim();
            String value = arr[1].trim();
            if (!modify(serviceConfig, fieldEditor, field, value)) {
                notfound.add(field);
            }
        }

        if (!notfound.isEmpty()) {
            displayNotFound(notfound);
            success = false;
        }
        return success;
    }

    /**
     * Modifies a given field or property in a ServiceConfiguration, using the a FieldEditor.
     * 
     * First it tries to find a field with the given name, then it tries with the
     * worker/interval/action properties.
     */
    protected boolean modify(ServiceConfiguration serviceConfig, FieldEditor fieldEditor, String field, String value) {
        boolean found = false;
        try {
            // Try to call the setter 
            fieldEditor.setValue(ServiceConfiguration.class.getName(), field, value, serviceConfig);
            getLogger().info("Updated field: " + field);
            getLogger().info("New field value: " + fieldEditor.getBeanValue(field, serviceConfig));
            found = true;
        } catch (FieldNotFoundException e) {
            // Check if it's in one of the Properties objects
            Properties props;

            props = serviceConfig.getWorkerProperties();
            if (props.containsKey(field) || field.startsWith("worker.")) {
                props.setProperty(field, value);
                getLogger().info("Updated worker property: " + field);
                serviceConfig.setWorkerProperties(props);
                getLogger().info("New worker property value: " + serviceConfig.getWorkerProperties().getProperty(field));
                found = true;
            }

            props = serviceConfig.getIntervalProperties();
            if (props.containsKey(field) || field.startsWith("interval.")) {
                props.setProperty(field, value);
                getLogger().info("Updated interval property: " + field);
                serviceConfig.setIntervalProperties(props);
                getLogger().info("New interval property value: " + serviceConfig.getIntervalProperties().getProperty(field));
                found = true;
            }

            props = serviceConfig.getActionProperties();
            if (props.containsKey(field) || field.startsWith("action.")) {
                props.setProperty(field, value);
                getLogger().info("Updated action property: " + field);
                serviceConfig.setActionProperties(props);
                getLogger().info("New action property value: " + serviceConfig.getActionProperties().getProperty(field));
                found = true;
            }

            if (!found) {
                getLogger().info(e.getMessage());
            }
        }
        return found;
    }

    /** Handles the -listFields and -listProperties options. */
    protected boolean handleListOptions(ServiceConfiguration serviceConfig, ParameterContainer parameters, String command) {
        final FieldEditor fieldEditor = new FieldEditor(getLogger());
        boolean hasOption = false;
        if (parameters.containsKey("-listFields")) {
            fieldEditor.listSetMethods(serviceConfig);
            hasOption = true;
        }
        if (parameters.containsKey("-listProperties")) {
            boolean displayedOne = false;
            displayedOne |= displayPropertiesHelp(serviceConfig.getWorkerProperties());
            displayedOne |= displayPropertiesHelp(serviceConfig.getIntervalProperties());
            displayedOne |= displayPropertiesHelp(serviceConfig.getActionProperties());
            if (!displayedOne) {
                // No properties
                getLogger().info(
                        "create".equals(command) ? "The -listProperties option can presently only be used with the edit command."
                                : "No properties have been set.");
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
        for (Entry<Object, Object> prop : props.entrySet()) {
            // We don't know the types but we can display the default values so the user can figure out.
            getLogger().info(prop.getKey() + " (current value = '" + prop.getValue() + "')");
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
            getLogger().info("    " + error);
        }
        getLogger().info("");
        getLogger().info("Changes were NOT saved!");
    }



}
