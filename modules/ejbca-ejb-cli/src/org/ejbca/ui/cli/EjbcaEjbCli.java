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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.util.PluginTool;

/**
 * Main entry point for the EJBCA EJB CLI
 */
public class EjbcaEjbCli {

	private static final Logger log = Logger.getLogger(EjbcaEjbCli.class);
	
	public static void main(String[] args) {
		List<CliCommand> commandList = new ArrayList<CliCommand>();
		List<String> mainCommands = new ArrayList<String>();
		List<Class<?>> list = PluginTool.getSome("org.ejbca.ui.cli", CliCommandPlugin.class, true);
		//List<Class<?>> list = PluginTool.getSome(null, CliCommandPlugin.class, true);	// This is painfully slow!
		// Extract all the commands from the plugins
		for (Class<?> command : list) {
			try {
				String mainCommand = (String) command.getMethod("getMainCommand", new Class[0]).invoke(command.newInstance(), new Object[0]);
				String subCommand = (String) command.getMethod("getSubCommand", new Class[0]).invoke(command.newInstance(), new Object[0]);
				String description = (String) command.getMethod("getDescription", new Class[0]).invoke(command.newInstance(), new Object[0]);
				if (/*mainCommand == null || mainCommand.trim().length()==0 ||*/ subCommand == null || subCommand.trim().length()==0 ||
						description == null || description.trim().length()==0) {
					log.warn("Will not register plugin class " + command.getName() + ": Required getter returned an empty String.");
					continue;
				}
				//log.debug(" main: " + mainCommand + " sub: " + subCommand + " description: " + description);
				commandList.add(new CliCommand(mainCommand, subCommand, description, command));
				if (!mainCommands.contains(mainCommand)) {
					mainCommands.add(mainCommand);
				}
			} catch (Exception e) {
				log.warn("Will not register plugin class " + command.getName() + ": " + e.getMessage());
				continue;
			}
		}
		// Look for (and execute if found) commands that don't have main command
		List<CliCommand> subTargetsOnly = new ArrayList<CliCommand>();
		for (CliCommand cliCommand : commandList) {
			if (cliCommand.getMainCommand() == null) {
				if (args.length>0 && cliCommand.getSubCommand().equalsIgnoreCase(args[0])) {
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
			if (args.length>0 && cliCommand.getMainCommand() != null && cliCommand.getMainCommand().equalsIgnoreCase(args[0])) {
				if (args.length>1 && cliCommand.getSubCommand().equalsIgnoreCase(args[1])) {
					executeCommand(cliCommand.getCommandClass(), args, true);
					return;
				}
				subTargets.add(cliCommand);
				subCommands.add(cliCommand.getSubCommand());
			}
		}
		// If we didn't execute something by now the command wasn't found
		if (subTargets.isEmpty()) {	/*args.length<2 && */
			String mainCommandsString = "";
			for (String mainCommand : mainCommands) {
				mainCommandsString += (mainCommandsString.length()==0?"":" | ") + (mainCommand!=null?mainCommand:"");
			}
			log.info("Missing or invalid argument. Use one of [" + mainCommandsString + "] to see additional sub commands.");
			if (!subTargetsOnly.isEmpty()) {
				log.info("Or use one of:");
				showSubCommands(subTargetsOnly);
			}
			return;
		} else {
			log.info("Available sub commands for '" + args[0] + "':");
			showSubCommands(subTargets);
		}
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
	private static void executeCommand(Class<?> commandClass, String[] args, boolean shiftArgs) {
		log.debug("Executing " + commandClass.getName());
		try {
			Class[] parameterTypes = new Class[1];
			parameterTypes[0] = String[].class;
			Method method = commandClass.getMethod("execute", parameterTypes);
			CliCommandPlugin instance = (CliCommandPlugin) commandClass.newInstance();
			if (shiftArgs) {
				args = shiftStringArray(args);
			}
			method.invoke(instance, (Object)args);
			return;
		} catch (InvocationTargetException e) {
			Throwable targetException = e.getTargetException();
			if (targetException instanceof IllegalAdminCommandException) {
				log.error(targetException.getMessage(), targetException);
			} else if (targetException instanceof ErrorAdminCommandException) {
				log.error("An error ocurred", targetException);
			}
		} catch (Exception e) {
			log.error("Could not run execute method for class " + commandClass, e);
		}
	}
	
	/**
	 * Remove the first entry in the String array
	 */
	public static String[] shiftStringArray(String[] input) {
		String[] output = new String[input.length-1];
		for (int i=1 ;i<input.length; i++) {
			output[i-1] = input[i];
		}
		return output;
	}
}
