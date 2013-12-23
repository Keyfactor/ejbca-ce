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
package org.ejbca.ui.cli.infrastructure.library;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin;

/**
 * A library class to register and interface with commands. 
 * 
 * @version $Id$
 *
 */

public enum CommandLibrary {
    INSTANCE;

    private static final String TAB = "    ";
    private static final String DELIMITER = "--------------------------------\n";

    private static final Logger log = Logger.getLogger(CommandLibrary.class);

    private Branch root = new Branch("");

    private CommandLibrary() {
        ServiceLoader<? extends CliCommandPlugin> serviceLoader = ServiceLoader.load(CliCommandPlugin.class);
        for (Iterator<? extends CliCommandPlugin> iterator = serviceLoader.iterator(); iterator.hasNext();) {
            CliCommandPlugin command = iterator.next();
            root.addChild(command, command.getCommandPath());
        }

    }

    public void findAndExecuteCommandFromParameters(String... parameters) {
        root.execute(parameters);
    }

    public void listRootCommands() {
        root.printManPage();
    }

    /**
     * 
     * @param args The full argument list from a command. Just pass the whole thing in there and the library will try to figure out if a command is 
     *              hidden in there somewhere.
     * @return true if a command can be found that matches the path in the args
     */
    public boolean doesCommandExist(String... args) {
        return root.doesCommandExist(args);
    }

    private static class Branch {
        private final String name;
        private Map<String, Branch> subBranches = new HashMap<String, Branch>();
        private Map<String, CliCommandPlugin> commands = new HashMap<String, CliCommandPlugin>();

        public Branch(String name) {
            this.name = name;
        }

        public boolean doesCommandExist(String... args) {
            if (args.length == 0) {
                return false;
            } else {
                String key = args[0];
                if (commands.containsKey(key)) {
                    return true;
                } else {
                    if (args.length > 1) {
                        if (subBranches.containsKey(key)) {
                            return subBranches.get(key).doesCommandExist(Arrays.copyOfRange(args, 1, args.length));
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }

        }

        public void addChild(CliCommandPlugin command, String... parameters) {
            if (parameters.length == 0) {
                if (commands.containsKey(command.getMainCommand())) {
                    throw new CliCommandLibraryConflictException("Command " + command.getMainCommand() + " has been added twice.");
                } else {
                    commands.put(command.getMainCommand(), command);
                }
            } else {
                Branch childBranch;
                final String childName = parameters[0];
                if (childName == command.getMainCommand() || command.getMainCommandAliases().contains(childName)) {
                    throw new CliCommandLibraryConflictException("Naming conflict when attempting to construct command library: " + childName);
                }
                if (subBranches.containsKey(childName)) {
                    childBranch = (Branch) subBranches.get(parameters[0]);
                } else {
                    childBranch = new Branch(childName);
                }
                childBranch.addChild(command, Arrays.copyOfRange(parameters, 1, parameters.length));
            }
        }

        public void printManPage() {
            StringBuffer stringBuffer = new StringBuffer();
            List<String> sortedSubCommandList = new ArrayList<String>();
            sortedSubCommandList.addAll(subBranches.keySet());
            Collections.sort(sortedSubCommandList);
            if (sortedSubCommandList.size() > 0) {
                stringBuffer.append(DELIMITER);
                stringBuffer.append("The following " + (name.length() > 0 ? "sub" : "") + "categories are available"
                        + (name.length() > 0 ? " for the command '" + name + "'" : "") + ":\n");
                stringBuffer.append("[");
                final String subcommandDelimiter = " | ";
                for (String subCommand : sortedSubCommandList) {
                    stringBuffer.append(subCommand + subcommandDelimiter);
                }
                stringBuffer.replace(stringBuffer.length() - subcommandDelimiter.length(), stringBuffer.length(), "]\n");
            }
            List<String> sortedCommandList = new ArrayList<String>();
            sortedCommandList.addAll(commands.keySet());
            Collections.sort(sortedCommandList);
            if (sortedCommandList.size() > 0) {
                stringBuffer.append(DELIMITER);
                stringBuffer.append((sortedSubCommandList.size() > 0 ? "And the " : "The ") + "following commands are available:\n");
                for (String command : sortedCommandList) {
                    stringBuffer.append(TAB + command + " - " + commands.get(command).getCommandDescription() + "\n");
                }
            }
            log.info(stringBuffer.toString());
        }

        public void execute(String... parameters) {
            if (parameters.length == 0) {
                //Should normally not happen, but let's fail nicely
                printManPage();
            } else {
                String key = parameters[0];
                if (commands.containsKey(key)) {
                    try {
                        commands.get(key).execute(Arrays.copyOfRange(parameters, 1, parameters.length));
                    } catch (IOException e) {
                        log.error("Unknown exception was thrown when writing to disc.", e);
                    }    
                } else if (!subBranches.containsKey(key)) {
                    printManPage();
                } else {
                    subBranches.get(key).execute(Arrays.copyOfRange(parameters, 1, parameters.length));
                }
            }
        }
    }

}
