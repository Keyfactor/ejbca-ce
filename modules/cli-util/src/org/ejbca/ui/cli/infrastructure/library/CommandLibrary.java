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
package org.ejbca.ui.cli.infrastructure.library;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CliCommandPlugin;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;

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

    private final Logger log = Logger.getLogger(CommandLibrary.class);

    private Branch root;

    private CommandLibrary() {
        synchronized (this) {
            if (root == null) {
                root = new Branch("");
                ServiceLoader<? extends CliCommandPlugin> serviceLoader = ServiceLoader.load(CliCommandPlugin.class);
                try {
                    for (Iterator<? extends CliCommandPlugin> iterator = serviceLoader.iterator(); iterator.hasNext();) {
                        CliCommandPlugin command = iterator.next();
                        root.addChild(command, command.getCommandPath());
                        if (!command.getCommandPathAliases().isEmpty()) {
                            Iterator<String[]> aliasIterator = command.getCommandPathAliases().iterator();
                            while (aliasIterator.hasNext()) {
                                root.addChild(command, true, aliasIterator.next());
                            }
                        }
                    }
                } catch (ServiceConfigurationError e) {
                    if (e.getCause() instanceof IllegalStateException && e.getCause().getLocalizedMessage().contains("No EJB receiver")) {
                        log.error("Error: CLI could not contact EJBCA instance. Either your application server is not up and running,"
                                + " EJBCA has not been deployed succesfully, or some firewall rule is blocking the CLI from the application server.");
                        System.exit(1);
                    } else {
                        throw e;
                    }
                }
            }
        }
    }

    public CommandResult findAndExecuteCommandFromParameters(String... parameters) {
        return root.execute(parameters);
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

    /**
     * A private subclass which describes a branch in the command tree. A branch can contain both a number of subbranches as well as a number of 
     * direct commands. 
     * 
     * @version $Id$
     *
     */
    private static class Branch {
        private final String name;
        //Denotes that a branch is an alias branch, i.e it won't show up in the man page. 
        private final boolean isAlternate;
        private Map<String, Branch> subBranches = new HashMap<String, Branch>();
        private Map<String, CliCommandPlugin> commands = new HashMap<String, CliCommandPlugin>();
        private Map<String, CliCommandPlugin> alternateCommands = new HashMap<String, CliCommandPlugin>();

        public Branch(final String name) {
            this.name = name;
            this.isAlternate = false;
        }

        public Branch(final String name, final boolean isAlternate) {
            this.name = name;
            this.isAlternate = isAlternate;
        }

        /**
         * Adds a child branch 
         * 
         * @param command the command to add
         * @param path the remaining path elements
         */
        public void addChild(CliCommandPlugin command, String... path) {
            addChild(command, false, path);
        }

        /**
         * Recursively adds a child branch 
         * 
         * @param command the command
         * @param true if the path is an alternate
         * @param path the remaining path elements
         */
        public void addChild(CliCommandPlugin command, boolean isAlternatePath, String... path) {
            if (path.length == 0) {
                Iterator<String> aliases = command.getMainCommandAliases().iterator();
                while (aliases.hasNext()) {
                    String alias = aliases.next();             
                    if (commands.containsKey(alias)) {
                        throw new CliCommandLibraryConflictException("Command alias" + alias + " for command " + command.getMainCommand()
                                + " has been added twice.");
                    } else if (alternateCommands.containsKey(alias)) {
                        throw new CliCommandLibraryConflictException("Command alias" + alias + " for command " + command.getMainCommand()
                                + " has been added twice.");
                    } else {
                        alternateCommands.put(alias, command);
                    }
                }
                if (commands.containsKey(command.getMainCommand())) {
                    throw new CliCommandLibraryConflictException("Command " + command.getMainCommand() + "(" + command.getClass()
                            + ") has been added twice. Conflicts with " + commands.get(command.getMainCommand()).getClass());
                } else {
                    commands.put(command.getMainCommand(), command);
                }
            } else {
                Branch childBranch;
                final String childName = path[0];
                if (childName == command.getMainCommand() || command.getMainCommandAliases().contains(childName)) {
                    throw new CliCommandLibraryConflictException("Naming conflict when attempting to construct command library: " + childName);
                }
                if (subBranches.containsKey(childName)) {
                    childBranch = (Branch) subBranches.get(path[0]);
                } else {
                    childBranch = new Branch(childName, isAlternatePath);
                    subBranches.put(childBranch.getKey(), childBranch);
                }
                childBranch.addChild(command, Arrays.copyOfRange(path, 1, path.length));
            }
        }

        /**
         * 
         * @param args a list of arguments
         * @return true if command exists, or if a request to print the man page of a subbranch has come in. 
         */
        public boolean doesCommandExist(String... args) {
            if (args.length == 0) {
                return false;
            } else {
                String key = args[0].toLowerCase(Locale.ENGLISH);
                if (commands.containsKey(key)) {
                    return true;
                } else if (alternateCommands.containsKey(key)) {
                    return true;
                } else {
                    if (subBranches.containsKey(key)) {
                        String[] subset = Arrays.copyOfRange(args, 1, args.length);
                        if (subset.length == 0) {
                            //Counts as a request for a man page
                            return true;
                        } else {
                            return subBranches.get(key).doesCommandExist(subset);
                        }
                    } else {
                        return false;
                    }
                }
            }

        }

        public void printManPage() {
            StringBuffer stringBuffer = new StringBuffer();
            List<String> sortedSubCommandList = new ArrayList<String>();
            for (String subBranchKey : subBranches.keySet()) {
                Branch subBranch = subBranches.get(subBranchKey);
                if (!subBranch.isAlternate()) {
                    sortedSubCommandList.add(subBranch.getName());
                }
            }

            Collections.sort(sortedSubCommandList, new Comparator<String>() {
                @Override
                public int compare(String o1, String o2) {
                    return o1.compareToIgnoreCase(o2);
                }
            });
            if (sortedSubCommandList.size() > 0) {
                stringBuffer.append(DELIMITER);
                stringBuffer.append("The following " + (name.length() > 0 ? "sub" : "") + "categories are available"
                        + (name.length() > 0 ? " for the command '" + name + "'" : "") + ":\n");
                stringBuffer.append(TAB + "[ ");
                final String subcommandDelimiter = " | ";
                for (String subCommand : sortedSubCommandList) {
                    stringBuffer.append(subCommand + subcommandDelimiter);
                }
                stringBuffer.replace(stringBuffer.length() - subcommandDelimiter.length(), stringBuffer.length(), " ]\n");
            }
            List<String> sortedCommandList = new ArrayList<String>();
            sortedCommandList.addAll(commands.keySet());
            Collections.sort(sortedCommandList, new Comparator<String>() {
                @Override
                public int compare(String o1, String o2) {
                    return o1.compareToIgnoreCase(o2);
                }
            });
            int longestCommandLength = 0;
            for (String command : sortedCommandList) {
                if (command.length() > longestCommandLength) {
                    longestCommandLength = command.length();
                }
            }
            String indent = tab(longestCommandLength / TAB.length() + 2);
            if (sortedCommandList.size() > 0) {
                stringBuffer.append(DELIMITER);
                stringBuffer.append((sortedSubCommandList.size() > 0 ? "And the " : "The ") + "following commands are available:\n");
                for (String command : sortedCommandList) {
                    stringBuffer.append(TAB + command + indent.substring(command.length()) + commands.get(command).getCommandDescription() + "\n");
                }
            }
            stringBuffer.append("\nType a command and \"--help\" for more information.\n");
            INSTANCE.log.info(stringBuffer.toString());
        }

        private final String tab(int indentation) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < indentation; i++) {
                sb.append(TAB);
            }
            return sb.toString();
        }

        public CommandResult execute(String... parameters) {
            if (parameters.length == 0) {
                //We only got to a branch
                if (isAlternate) {
                    INSTANCE.log.warn("WARNING: The path used is an unlisted alternate path and may be deprecated, and may cease to exist at any point."
                            + " Please start using the updated path as soon as possible.\n");
                }
                printManPage();
                return CommandResult.SUCCESS;
            } else {
                String key = parameters[0].toLowerCase(Locale.ENGLISH);
                if (commands.containsKey(key) || alternateCommands.containsKey(key)) {
                    if (isAlternate) {
                        INSTANCE.log.warn("WARNING: The path used is an unlisted alternate path and may be deprecated, and may cease to exist at any point."
                                + " Please start using the updated path as soon as possible.\n");
                    }
                    if(alternateCommands.containsKey(key)) {
                        INSTANCE.log.warn("WARNING: The command \"" + key + "\" used is an unlisted alternate command and may be deprecated, and may cease to exist at any point."
                                + " Please start using the updated command \"" + alternateCommands.get(key).getMainCommand() + "\" as soon as possible.\n");
                        return alternateCommands.get(key).execute(Arrays.copyOfRange(parameters, 1, parameters.length));
                    } else {
                        return commands.get(key).execute(Arrays.copyOfRange(parameters, 1, parameters.length));
                    }
                } else if (!subBranches.containsKey(key)) {
                    if (isAlternate) {
                        INSTANCE.log.warn("WARNING: The path used is an unlisted alternate path and may be deprecated, and may cease to exist at any point."
                                + " Please start using the updated path as soon as possible.\n");
                    }
                    printManPage();
                    return CommandResult.SUCCESS;
                } else {
                    return subBranches.get(key).execute(Arrays.copyOfRange(parameters, 1, parameters.length));
                }
            }
        }

        /**
         * 
         * @return the name, but in lowercase. 
         */
        private final String getKey() {
            return name.toLowerCase(Locale.ENGLISH);
        }

        private final String getName() {
            return name;
        }

        private final boolean isAlternate() {
            return isAlternate;
        }

    }

}
