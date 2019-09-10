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
package org.ejbca.ui.cli.infrastructure.command;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;

/**
 * Base class for all commands
 * 
 * @version $Id$
 *
 */
public abstract class CommandBase implements CliCommandPlugin {

    private static final String TAB = "    ";
    private static final String CR = "\n";

    protected final ParameterHandler parameterHandler;

    {
        parameterHandler = new ParameterHandler(getMainCommand());
        Parameter help = Parameter.createFlag(ParameterHandler.HELP_KEY, "");
        help.setAllowList(false);
        registerParameter(help);
        registerParameter(Parameter.createFlag(ParameterHandler.VERBOSE_KEY, "Set this value for verbose output of parameter values."));
    }

    /**
     * Prompts for "y" or "n".
     * 
     * @param prompt Prompt string. The string " (y/n) " will be appended.
     * @param defaultYes If "yes" should be the default. Otherwise "no" will be the default.
     * @return True if "yes" was answered, false if "no" was answered.
     */
    protected static boolean readYesNo(final String prompt, final boolean defaultYes) {
        final String promptLine = prompt + (defaultYes ? " (Y/n) " : " (y/N) ");
        while (true) { // until a valid response has been provided
            final String input = prompt(promptLine);
            if (input.isEmpty()) {
                System.out.println(defaultYes ? "Yes." : "No.");
                return defaultYes;
            } else if (input.equalsIgnoreCase("y")) {
                return true;
            } else if (input.equalsIgnoreCase("n")) {
                return false;
            } else {
                System.out.println("Input not recognized: '" + input + "'");
            }
        }
    }
    
    /**
     * Prompts for a string.
     * 
     * @param prompt Prompt string. It should explain to the user what should be entered.
     * @return The entered string, minus leading/trailing whitespace. Never null.
     * @throws IllegalArgumentException On End-Of-File.
     */
    protected static String prompt(final String promptLine) {
        System.out.print(promptLine);
        System.out.flush();
        try (final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in))) {
            final String reply = bufferedReader.readLine();
            if (reply == null) {
                throw new IllegalArgumentException("Got End-Of-File when trying to read answer from user");
            }
            return reply.trim();
        } catch (IOException e) {
            throw new IllegalStateException("Unknown IOException occurred.", e);
        }
    }

    @Override
    public CommandResult execute(String... arguments) {
        ParameterContainer parameters = parameterHandler.parseParameters(arguments);
        if (parameters == null) {
            //Parameters couldn't be parsed, but this should already be handled. 
            return CommandResult.CLI_FAILURE;
        }
        if (parameters.containsKey(ParameterHandler.HELP_KEY)) {
            printManPage();
            return CommandResult.SUCCESS;
        } else {
            return execute(parameters);
        }
    }

    // Return an empty set for commands without aliases
    @Override
    public Set<String> getMainCommandAliases() {
        return new HashSet<>();
    }

    // Return an empty path for top level commands
    @Override
    public String[] getCommandPath() {
        return new String[] {};
    }

    // Return an empty set for commands without path aliases
    @Override
    public Set<String[]> getCommandPathAliases() {
        return new HashSet<>();
    }

    /**
     * Execute commands on a local level, sans boilerplate code
     * 
     * @param parameters a map of the parameters.  
     */
    protected abstract CommandResult execute(ParameterContainer parameters);

    protected void registerParameter(Parameter parameter) {
        parameterHandler.registerParameter(parameter);
    }

    protected boolean isParameterRegistered(final String keyword) {
        return parameterHandler.isParameterRegistered(keyword);
    }

    public abstract String getFullHelpText();

    public abstract String getImplementationName();

    /**
     * 
     * @return true if synopsis is to be printed for this command.
     */
    protected boolean doPrintSynopsis() {
        return true;
    }

    /**
     * Prints an auto formatted man-esque page for this command.
     */
    protected void printManPage() {
        StringBuffer sb = new StringBuffer();
        sb.append(CR);
        sb.append(bold(getMainCommand().toUpperCase()) + tab(3) + getImplementationName() + " Commands Manual" + tab(3)
                + bold(getMainCommand().toUpperCase()) + CR);
        sb.append(CR);
        sb.append(bold("NAME") + CR);
        sb.append(TAB + getMainCommand() + " - " + getCommandDescription() + CR);
        sb.append(CR);
        final List<String> mandatoryParameters = parameterHandler.getMandatoryParameters();
        final List<String> optionalParameters = parameterHandler.getOptionalParameters();
        final LinkedList<String> standaloneParameters = parameterHandler.getStandaloneParameters();
        sb.append(bold("SYNOPSIS") + CR);
        if (doPrintSynopsis()) {
            if (standaloneParameters.size() > 0) {
                //Only make this synopsis if there are standalone parameters
                sb.append(TAB + getMainCommand());
                Set<String> usedMandatories = new HashSet<>();
                for (String parameterString : standaloneParameters) {
                    Parameter parameter = parameterHandler.getRegisteredParameter(parameterString);
                    sb.append(" <" + parameter.getName().toUpperCase().replaceAll(" ", "_") + ">");
                    if (parameter.isMandatory()) {
                        usedMandatories.add(parameterString);
                    }
                }
                for (String parameterString : mandatoryParameters) {
                    if (!usedMandatories.contains(parameterString)) {
                        Parameter parameter = parameterHandler.getRegisteredParameter(parameterString);
                        sb.append(" " + parameter.getKeyWord() + " <" + parameter.getName().toUpperCase().replaceAll(" ", "_") + ">");
                    }
                }
                if (optionalParameters.size() > 0) {
                    sb.append(" [OPTIONAL PARAMETERS]");
                }
                sb.append(CR);
            }
            sb.append(TAB + getMainCommand());
            for (String parameterString : mandatoryParameters) {
                Parameter parameter = parameterHandler.getRegisteredParameter(parameterString);
                sb.append(" " + parameter.getKeyWord() + " <" + parameter.getName().toUpperCase().replaceAll(" ", "_") + ">");
            }
            if (optionalParameters.size() > 0) {
                sb.append(" [OPTIONAL PARAMETERS]");
            }
            sb.append(CR);
            sb.append(CR);
        } else {
            sb.append(TAB + "Synposis not printed for this command." + CR + CR);
        }
        sb.append(bold("DESCRIPTION") + CR);
        for (String formattedString : splitStringIntoLines(getFullHelpText(), 120)) {
            sb.append(TAB + formattedString + CR);
        }
        sb.append(CR);
        sb.append(bold("PARAMETERS") + CR);
        if (mandatoryParameters.size() > 0) {
            Collections.sort(mandatoryParameters);
            sb.append(TAB + "Mandatory parameters:" + CR);
            sb.append(formatParameterList(mandatoryParameters));
            sb.append(CR);
        }
        if (optionalParameters.size() > 0) {
            Collections.sort(optionalParameters);
            sb.append(TAB + "Optional parameters:" + CR);
            sb.append(formatParameterList(optionalParameters));
        }
        getLogger().info(sb.toString());
    }

    protected static String bold(String text) {
        return (char) 27 + "[1m" + text + (char) 27 + "[0m";
    }

    private String formatParameterList(List<String> parameterNames) {
        StringBuilder sb = new StringBuilder();
        for (String parameterName : parameterNames) {
            Parameter parameter = parameterHandler.getRegisteredParameter(parameterName);
            if (parameter.allowList()) {
                sb.append(tab(2) + parameter.getKeyWord());
                switch (parameter.getParameterMode()) {
                case ARGUMENT:
                    sb.append(" <" + parameter.getName().toUpperCase().replaceAll(" ", "_") + ">"
                            + (parameter.isStandAlone() ? " (Switch is not required)" : "") + CR);
                    break;
                case INPUT:
                    sb.append(" <User will be prompted>" + CR);
                    break;
                case PASSWORD:
                    sb.append(" <User will be prompted, input will not be shown>" + CR);
                    break;
                default:
                    sb.append(CR);
                    break;
                }
                for (String line : splitStringIntoLines(parameter.getInstruction(), 80)) {
                    sb.append(tab(3) + line + CR);
                }
            }
        }
        return sb.toString();
    }

    private static String tab(int times) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < times; i++) {
            sb.append(TAB);
        }
        return sb.toString();
    }

    /**
     * Private utility method that takes a string and splits it by line length
     * 
     * @param input the string to format 
     * @param lineLength the length of each line
     * @return an list of strings, no longer than the given length
     */
    public static List<String> splitStringIntoLines(String input, int lineLength) {
        List<String> result = new ArrayList<>();
        while (input.length() > lineLength || input.contains("\n")) {
            int newline = input.indexOf("\n");
            if (newline != -1 && newline < lineLength) {
                String line = input.substring(0, newline);
                result.add(line);
                input = input.substring(newline + 1);
            } else {
                String subString = input.substring(0, lineLength);
                int lastSpace = subString.lastIndexOf(" ");
                if (lastSpace == -1) {
                    // lineLength characters without a single space. Eh...fine.
                    lastSpace = lineLength;
                }
                String line = input.substring(0, lastSpace);
                result.add(line);
                input = input.substring(lastSpace + 1);
            }
        }
        if (!input.equals("")) {
            result.add(input);
        }
        return result;
    }

    protected abstract Logger getLogger();

    protected static String formatTable(int tabs, String[] titles, List<String[]> contents) {
        int[] offset = new int[titles.length];
        //Validate contents and figure out tab size per column
        for (int i = 0; i < titles.length; i++) {
            offset[i] = titles[i].length() / TAB.length() + 2;
        }
        for (String[] row : contents) {
            if (row.length < titles.length) {
                throw new IllegalArgumentException("Invalid column length. Titlebar had " + titles.length + " columns, while content row had "
                        + row.length);
            }
            for (int i = 0; i < row.length; i++) {
                int rowOffset = row[i].length() / TAB.length() + 2;
                if (rowOffset > offset[i]) {
                    offset[i] = rowOffset;
                }
            }
        }
        StringBuilder stringBuilder = new StringBuilder();
        //Build title bar
        stringBuilder.append(tab(tabs));
        for (int i = 0; i < titles.length; i++) {
            String title = titles[i];
            String whitespace = tab(offset[i]);
            stringBuilder.append(bold(title) + whitespace.substring(title.length(), whitespace.length()));
        }
        stringBuilder.append("\n");
        //And add contents
        for (String[] row : contents) {
            stringBuilder.append(tab(tabs));
            for (int i = 0; i < row.length; i++) {
                String rowWord = row[i];
                String whitespace = tab(offset[i]);
                stringBuilder.append(rowWord + whitespace.substring(rowWord.length(), whitespace.length()));
            }
            stringBuilder.append("\n");

        }
        return stringBuilder.toString();
    }

}
