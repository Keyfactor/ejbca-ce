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
package org.ejbca.ui.cli.infrastructure.parameter;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;

/**
 * Class for handling parameters in commands
 * 
 * @version $Id$
 *
 */
public class ParameterHandler {

    public static final String HELP_KEY = "--help";
    public static final String VERBOSE_KEY = "--verbose";

    private static final Logger log = Logger.getLogger(ParameterHandler.class);

    private static final String TAB = "    ";
    private static final String CR = "\n";

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

    public Parameter getRegisteredParameter(final String key) {
        return parameterMap.get(key);
    }

    public boolean isParameterRegistered(final String keyword) {
        return parameterMap.containsKey(keyword);
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

    /**
     * This method takes the parameters given by the command line and returns them as a map keyed to the flags
     * 
     * @param arguments the parameters as given by the command line
     * @return a map of parameters and their values, null if command cannot run.
     */
    public ParameterContainer parseParameters(String... arguments) {
        ParameterContainer result = new ParameterContainer();
        List<String> argumentList = new ArrayList<String>();
        boolean verbose = false;
        for (int i = 0; i < arguments.length; i++) {
            String argument = arguments[i];
            //Glue together any quotes that may be mismatched due to spaces
            if ((argument.startsWith("'") && !argument.endsWith("'")) || (argument.startsWith("\"") && !argument.endsWith("\""))) {
                final String quoteType = argument.substring(0, 1);
                for (int j = i + 1; j < arguments.length; j++) {
                    if (arguments[j].startsWith(quoteType)) {
                        log.error("ERROR: Unclosed quote: " + argument);
                        return null;
                    } else if (arguments[j].endsWith(quoteType)) {
                        argument += " " + arguments[j];
                        i = j;
                        break;
                    } else {
                        argument += " " + arguments[j];
                    }
                }
            }
            if (argument.equals(VERBOSE_KEY)) {
                verbose = true;
            } else {
                argumentList.add(argument);
            }
            if (log.isDebugEnabled()) {
                log.debug("ARGUMENT: " + argument);
            }
        }

        List<String> unknownArguments = new ArrayList<String>();
        List<Parameter> missingArguments = new ArrayList<Parameter>();
        LinkedList<String> standaloneParametersDefensiveCopy = new LinkedList<String>(standaloneParameters);
        //Get a list of all parameters
        for (int i = 0; i < argumentList.size(); i++) {
            boolean isStandalone = false;
            String parameterString = argumentList.get(i);
            //Handle the case where the command line may have split up an argument with a a space that's in quotes

            //Handle the case of -argument=value, but ignore if in quotes
            if (parameterString.matches("^-.*=.*")) {
                //If so, split the switch and value up.
                int valueIndex = parameterString.indexOf("=") + 1;
                argumentList.add(i + 1,
                        (valueIndex >= parameterString.length() ? "" : parameterString.substring(valueIndex, parameterString.length())));
                parameterString = parameterString.substring(0, valueIndex - 1);
            }
            if (result.containsKey(parameterString)) {
                log.info("ERROR: Multiple parameters of type " + parameterString + " encountered.");
                return null;
            }
            Parameter parameter = parameterMap.get(parameterString);
            String value;
            if (parameter == null) {
                //Presume that it might be a standalone argument
                if (standaloneParametersDefensiveCopy.size() > 0 && !parameterString.startsWith("-")) {
                    value = parameterString;
                    parameterString = standaloneParametersDefensiveCopy.removeFirst();
                    isStandalone = true;
                } else {
                    unknownArguments.add(parameterString);
                    continue;
                }
            } else {
                if (parameter.getParameterMode() == ParameterMode.ARGUMENT) {
                    //Check that the following argument exists and isn't a switch (ignoring negative numbers)
                    if ((i + 1) >= argumentList.size() || argumentList.get(i + 1).matches("^-[A-z]+$")) {
                        log.info("ERROR: Missing argument.");
                        log.info(TAB + parameterString + " is an argument and requires a parameter following it.");
                        return null;
                    } else {
                        value = argumentList.get(i + 1);
                        i++;
                    }
                } else if (parameter.getParameterMode() == ParameterMode.FLAG) {
                    value = "";
                } else if (parameter.getParameterMode() == ParameterMode.INPUT) {
                    log.info("Enter value for " + parameterString + ": ");
                    value = System.console().readLine();
                } else if (parameter.getParameterMode() == ParameterMode.PASSWORD) {
                    log.info("Enter password for parameter (" + parameterString + "): ");
                    value = new String(System.console().readPassword());
                } else {
                    throw new IllegalStateException(parameter.getParameterMode().name() + " was an unknown parameter type.");
                } 
                standaloneParametersDefensiveCopy.remove(parameterString);
            }
            if (verbose) {
                if (!StringUtils.isEmpty(value) && (parameter == null || (parameter.getParameterMode() != ParameterMode.PASSWORD && parameter.getParameterMode() != ParameterMode.FLAG))) {
                    log.error("SETTING: " + parameterString + " as " + value);
                }
            }
            
            //Lastly, strip any quotes 
            if ((value.startsWith("'") && value.endsWith("'")) || (value.startsWith("\"") && value.endsWith("\""))) {
                value = value.substring(1, value.length() - 1);
            }
            result.put(parameterString, value, isStandalone);
        }

        if (result.containsKey(HELP_KEY)) {
            //Do not validate if help was requested
            return result;
        }

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
            sb.append("ERROR: Incorrect parameter usage.");
            if (unknownArguments.size() > 0) {
                sb.append("\n");
                sb.append(tab(1) + "The following arguments are unknown:\n");
                for (String unknownParameter : unknownArguments) {
                    sb.append(tab(2) + unknownParameter + "\n");
                }
            }
            if (missingArguments.size() > 0) {
                sb.append("\n");
                sb.append(tab(1) + "The following mandatory arguments are missing or poorly formed, use --help for more information:\n");
                int longestKeyWord = 0;
                for (Parameter missingParameter : missingArguments) {
                    if (missingParameter.getKeyWord().length() > longestKeyWord) {
                        longestKeyWord = missingParameter.getKeyWord().length();
                    }
                }
                String indent = tab(longestKeyWord / TAB.length() + 2);
                for (Parameter missingParameter : missingArguments) {
                    sb.append(tab(2) + missingParameter.getKeyWord() + indent.substring(missingParameter.getKeyWord().length()));
                    List<String> lines = CommandBase.splitStringIntoLines(missingParameter.getInstruction(), 120 - indent.length());
                    if (lines.size() > 0) {
                        sb.append(lines.get(0) + "\n");
                        for (int i = 1; i < lines.size(); i++) {
                            sb.append(tab(2) + indent + lines.get(i) + "\n");
                        }
                    }

                }
            }
            sb.append(CR + "Run command with \"" + HELP_KEY + "\" to see full manual page.");
            log.info(sb);
            return null;
        }
    }

    /**
     * @return the mandatoryParameters
     */
    public List<String> getMandatoryParameters() {
        return mandatoryParameters;
    }

    /**
     * @return the optionalParameters
     */
    public List<String> getOptionalParameters() {
        return optionalParameters;
    }

    /**
     * @return the standaloneParameters
     */
    public LinkedList<String> getStandaloneParameters() {
        return standaloneParameters;
    }

}
