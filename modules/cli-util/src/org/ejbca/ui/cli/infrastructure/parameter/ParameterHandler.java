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
package org.ejbca.ui.cli.infrastructure.parameter;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;

/**
 * Class for handling parameters in commands
 * 
 * @version $Id: ParameterHandler.java 17791 2013-10-10 21:01:33Z samuellb $
 *
 */
public class ParameterHandler {

    private static final Logger log = Logger.getLogger(ParameterHandler.class);

    private static final String TAB = "    ";
    private static final String CR = "\n";

    private static final String HELP_KEY = "--help";

    private final String commandName;

    private final Map<String, Parameter> parameterMap = new HashMap<String, Parameter>();
    private final List<String> mandatoryParameters = new ArrayList<String>();
    private final List<String> optionalParameters = new ArrayList<String>();
    private final LinkedList<String> standaloneParameters = new LinkedList<String>();

    public ParameterHandler(String commandName) {
        this.commandName = commandName;
    }

    public String getCommandName() {
        return commandName;
    }

    public void registerParameter(Parameter parameter) {
        final String keyWord = parameter.getKeyWord();
        parameterMap.put(keyWord, parameter);
        if (parameter.isMandatory()) {
            mandatoryParameters.add(keyWord);
        } else {
            optionalParameters.add(keyWord);
        }
        if (parameter.isStandAlone()) {
            standaloneParameters.add(keyWord);
        }
    }

    private String tab(int times) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < times; i++) {
            sb.append(TAB);
        }
        return sb.toString();
    }

    private String bold(String text) {
        return (char) 27 + "[1m" + text + (char) 27 + "[0m";
    }

    /**
     * Prints an auto formatted man-esque page for this command.
     */
    private void printManPage(CommandBase command) {
        StringBuffer sb = new StringBuffer();
        sb.append(CR);
        sb.append(bold(commandName.toUpperCase()) + tab(3) + command.getImplementationName() + " Commands Manual" + tab(3)
                + bold(commandName.toUpperCase()) + CR);
        sb.append(CR);
        sb.append(bold("NAME") + CR);
        sb.append(TAB + commandName + " - " + command.getCommandDescription() + CR);
        sb.append(CR);
        sb.append(bold("DESCRIPTION") + CR);
        for (String formattedString : splitStringIntoLines(command.getFullHelpText(), 80)) {
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
            sb.append(CR);
        }
        log.info(sb.toString());
    }

    private String formatParameterList(List<String> parameterNames) {
        StringBuilder sb = new StringBuilder();
        for (String parameterName : parameterNames) {
            Parameter parameter = parameterMap.get(parameterName);
            sb.append(tab(2) + parameter.getKeyWord());
            switch (parameter.getParameterMode()) {
            case ARGUMENT:
                sb.append(" <" + parameter.getName().toUpperCase() + ">" + CR);
                break;
            case INPUT:
                sb.append(" <user will be prompted>" + CR);
                break;
            case PASSWORD:
                sb.append(" <user will be prompted, input will not be shown>" + CR);
                break;
            default:
                sb.append(CR);
                break;
            }
            sb.append(tab(3) + parameter.getInstruction() + CR);
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
    private static List<String> splitStringIntoLines(String input, int lineLength) {
        List<String> result = new ArrayList<String>();
        while (input.length() > lineLength) {
            int lastSpace = input.substring(0, lineLength).lastIndexOf(" ");
            result.add(input.substring(0, lastSpace));
            input = input.substring(lastSpace + 1);
        }
        if (!input.equals("")) {
            result.add(input);
        }
        return result;
    }

    /**
     * This method takes the parameters given by the command line and returns them as a map keyed to the flags
     * 
     * @param arguments the parameters as given by the command line
     * @return a map of parameters and their values
     */
    public Map<String, String> parseParameters(CommandBase callback, String... arguments) {
        Map<String, String> result = new HashMap<String, String>();
        List<String> argumentList = new ArrayList<String>(Arrays.asList(arguments));
        List<String> unknownArguments = new ArrayList<String>();
        List<Parameter> missingArguments = new ArrayList<Parameter>();
        //Get a list of all parameters
        for (int i = 0; i < argumentList.size(); i++) {
            String parameterString = argumentList.get(i);
            if (parameterString.toLowerCase().equals(HELP_KEY)) {
                printManPage(callback);
                return null;
            }
            Parameter parameter = parameterMap.get(parameterString);
            String value;
            if (parameter == null) {
                //Presume that it might be a standalone argument
                if (standaloneParameters.size() > 0 && !parameterString.startsWith("-")) {
                    value = parameterString;
                    parameterString = standaloneParameters.removeFirst();

                } else {
                    unknownArguments.add(parameterString);
                    continue;
                }
            } else {
                if (parameter.getParameterMode() == ParameterMode.ARGUMENT) {
                    value = argumentList.get(i + 1);
                    i++;
                } else if (parameter.getParameterMode() == ParameterMode.FLAG) {
                    value = "";
                } else if (parameter.getParameterMode() == ParameterMode.INPUT) {
                    log.info("Enter value for " + parameterString + ": ");
                    value = System.console().readLine();
                } else if (parameter.getParameterMode() == ParameterMode.PASSWORD) {
                    log.info("Password (" + parameterString + "): ");
                    value = new String(System.console().readPassword());
                } else {
                    throw new IllegalStateException(parameter.getParameterMode().name() + " was an unknown parameter type.");
                }
            }
            result.put(parameterString, value);
        }
        callback.handleUserPasswordParams(result);
        //Check for mandatory parameters
        for (final String mandatoryParameter : mandatoryParameters) {
            if (!result.containsKey(mandatoryParameter)) {
                missingArguments.add(parameterMap.get(mandatoryParameter));
            }
        }
        if (unknownArguments.size() == 0 && missingArguments.size() == 0) {
            return result;
        } else {
            StringBuilder sb = new StringBuilder();
            sb.append("ERROR" + TAB + "Incorrect parameter usage.");
            if (unknownArguments.size() > 0) {
                sb.append("\n");
                sb.append(tab(1) + "The following arguments are unknown:\n");
                for (String unknownParameter : unknownArguments) {
                    sb.append(tab(2) + unknownParameter + "\n");
                }
            }
            if (missingArguments.size() > 0) {
                sb.append("\n");
                sb.append(tab(1) + "The following mandatory arguments are missing:\n");
                for (Parameter missingParameter : missingArguments) {
                    sb.append(tab(2) + missingParameter.getName() + " (" + missingParameter.getKeyWord() + ")\n");
                }
            }
            sb.append(CR + "Run command with \"" + HELP_KEY + "\" to see full manual page.");
            log.info(sb);

            return null;
        }
    }

}
