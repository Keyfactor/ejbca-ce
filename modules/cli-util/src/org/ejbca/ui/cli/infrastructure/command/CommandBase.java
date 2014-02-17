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
package org.ejbca.ui.cli.infrastructure.command;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.ejbca.ui.cli.infrastructure.io.OverwriteResponse;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;

/**
 * Base class for all commands
 * 
 * @version $Id: CommandBase.java 17791 2013-10-10 21:01:33Z samuellb $
 *
 */
public abstract class CommandBase implements CliCommandPlugin {
    
    protected final ParameterHandler parameterHandler = new ParameterHandler(getMainCommand());

    protected static OverwriteResponse getValueFoundResponse(OverwriteResponse defaultResponse) {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        try {
            while (true) { // until a valid response has been provided
                System.out.print(OverwriteResponse.getQueryText() + " [default=" + defaultResponse.getResponse().toUpperCase() + "] ");
                System.out.flush();
    
                String input = bufferedReader.readLine();
                if (input.isEmpty()) {
                    return defaultResponse;
                } else {
                    OverwriteResponse result = OverwriteResponse.getResponseFromInput(input);
                    if (result == null) {
                        System.out.println("Input not recognized: '" + input + "'");
                    } else {
                        return result;
                    }
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Unknown IOException occurred.", e);
        }
    }

    @Override
    public void execute(String... arguments) throws IOException {
        Map<String, String> parameters = parameterHandler.parseParameters(this, arguments);
        if(parameters == null) {
            //Parameters couldn't be parsed, but this should already be handled. 
            return;
        }
        execute(parameters);
    }
    
    // Return an empty set for commands without aliases
    @Override
    public Set<String> getMainCommandAliases() {
        return new HashSet<String>();
    }

    // Return an empty path for top level commands
    @Override
    public String[] getCommandPath() {
        return new String[]{};
    }

    // Return an empty set for commands without path aliases
    @Override
    public Set<String[]> getCommandPathAliases() {
        return new HashSet<String[]>();
    }
    
    /**
     * Execute commands on a local level, sans boilerplate code
     * 
     * @param parameters a map of the parameters.  
     */
    protected abstract void execute(Map<String, String> parameters);
    
    protected void registerParameter(Parameter parameter) {
        parameterHandler.registerParameter(parameter);
    }
   
    public abstract String getFullHelpText();
    
    public abstract String getImplementationName();
}
