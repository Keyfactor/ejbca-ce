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
package org.ejbca.ui.cli;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.util.PluginTool;

/**
 * Helper that searches the specified package and sub-packages for classes
 * that implement the CliCommandPlugin interface. It will also list all
 * found commands if no parameters. Otherwise it will execute the command. 
 *  
 * @version $Id$
 */
public class CliCommandHelper {
    
    private static final Logger log = Logger.getLogger(CliCommandHelper.class);

    public static void searchAndRun(String[] args, String basePackage) {
        List<CliCommand> commandList = new ArrayList<CliCommand>();
        List<String> mainCommands = new ArrayList<String>();
        List<Class<?>> list = PluginTool.getSome(basePackage, CliCommandPlugin.class, true);
        // List<Class<?>> list = PluginTool.getSome(null, CliCommandPlugin.class, true); // This is painfully slow!
        // Extract all the commands from the plugins
        for (final Class<?> command : list) {
            try {
                final Object object = command.newInstance();
                if (!(object instanceof CliCommandPlugin)) {
                    log.warn("Will not register plugin class " + command.getName() + ": Not an instance of CliCommandPlugin.");
                    continue;
                }
                final CliCommandPlugin cliCommandPlugin = (CliCommandPlugin) object;
                final String mainCommand = cliCommandPlugin.getMainCommand();
                final String subCommand = cliCommandPlugin.getSubCommand();
                final String description = cliCommandPlugin.getDescription();
                if (/*mainCommand == null || mainCommand.trim().length()==0 ||*/subCommand == null || subCommand.trim().length() == 0
                        || description == null || description.trim().length() == 0) {
                    log.warn("Will not register plugin class " + command.getName() + ": Required getter returned an empty String.");
                    continue;
                }
                // log.debug(" main: " + mainCommand + " sub: " + subCommand + " description: " + description);
                commandList.add(new CliCommand(mainCommand, subCommand, description, (Class<CliCommandPlugin>) command));
                if (!mainCommands.contains(mainCommand)) {
                    mainCommands.add(mainCommand);
                }
            } catch (Exception e) {
                log.warn("Will not register plugin class " + command.getName() + ": " + e.getMessage());
                log.debug("Will not register plugin class " + command.getName() + ": ", e);
                continue;
            }
        }
        // Look for (and execute if found) commands that don't have main command
        List<CliCommand> subTargetsOnly = new ArrayList<CliCommand>();
        for (CliCommand cliCommand : commandList) {
            if (cliCommand.getMainCommand() == null) {
                if (args.length > 0 && cliCommand.getSubCommand().equalsIgnoreCase(args[0])) {
                    executeCommand(cliCommand.getCommandClass(), args, false);
                    return;
                }
                subTargetsOnly.add(cliCommand);
            }
        }
        // Look for all sub commands (and execute if found)
        List<CliCommand> subTargets = new ArrayList<CliCommand>();
        List<String> subCommands = new ArrayList<String>();
        for (CliCommand cliCommand : commandList) {
            if (args.length > 0 && cliCommand.getMainCommand() != null && cliCommand.getMainCommand().equalsIgnoreCase(args[0])) {
                if (args.length > 1 && cliCommand.getSubCommand().equalsIgnoreCase(args[1])) {
                    executeCommand(cliCommand.getCommandClass(), args, true);
                    return;
                }
                subTargets.add(cliCommand);
                subCommands.add(cliCommand.getSubCommand());
            }
        }
        // If we didn't execute something by now the command wasn't found
        if (subTargets.isEmpty()) { /*args.length<2 && */
            String mainCommandsString = "";
            for (String mainCommand : mainCommands) {
                mainCommandsString += (mainCommandsString.length() == 0 ? "" : " | ") + (mainCommand != null ? mainCommand : "");
            }
            if (mainCommandsString.length()>0) {
                log.info("Missing or invalid argument. Use one of [" + mainCommandsString + "] to see additional sub commands.");
                if (!subTargetsOnly.isEmpty()) {
                    log.info("Or use one of:");
                }
            }
            if (!subTargetsOnly.isEmpty()) {
                showSubCommands(subTargetsOnly);
            }
            return;
        }
        log.info("Available sub commands for '" + args[0] + "':");
        showSubCommands(subTargets);
    }

    private static void showSubCommands(List<CliCommand> list) {
        Collections.sort(list);
        for (CliCommand cliCommand : list) {
            log.info(String.format("  %-20s %s", cliCommand.getSubCommand(), cliCommand.getDescription()));
        }
    }

    /**
     * 
     */
    private static void executeCommand(Class<CliCommandPlugin> commandClass, String[] args, boolean shiftArgs) {
        log.debug("Executing " + commandClass.getName());
        try {
            final CliCommandPlugin instance = commandClass.newInstance();
            instance.execute(shiftArgs ? shiftStringArray(args) : args);
            return;
        } catch (Exception e) {
            log.error("Could not run execute method for class " + commandClass.getName(), e);
            System.exit(1);
        }
    }

    /**
     * Remove the first entry in the String array
     */
    private static String[] shiftStringArray(String[] input) {
        String[] output = new String[input.length - 1];
        for (int i = 1; i < input.length; i++) {
            output[i - 1] = input[i];
        }
        return output;
    }
}
