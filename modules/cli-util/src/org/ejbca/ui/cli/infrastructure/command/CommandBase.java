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
import java.security.Principal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.authentication.cli.exception.CliAuthenticationFailedException;
import org.ejbca.ui.cli.infrastructure.io.ValueFoundResponse;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Base class for all commands
 * 
 * @version $Id: CommandBase.java 17791 2013-10-10 21:01:33Z samuellb $
 *
 */
public abstract class CommandBase implements CliCommandPlugin {

    public static final String USERNAME_KEY = "-u";
    public static final String PASSWORD_KEY = "-p";

    private String password = null;
    private String username = null;
    
    private final ParameterHandler parameterHandler = new ParameterHandler(getMainCommand());

    {
        registerDefaultParameters();
    }
    
    /**
     * Extracts -u and -p parameters, similar to BaseCommand.parseUsernameAndPasswordFromArgs,
     * but using a Map<String,String> instead of String[] for the arguments.
     */
    public void handleUserPasswordParams(Map<String, String> parameters) {
        final String usernameFromArgs = parameters.get(USERNAME_KEY);
        final String usernameFromConfig = EjbcaConfiguration.getCliDefaultUser();

        if (usernameFromArgs != null) {
            username = usernameFromArgs;
        } else if (usernameFromConfig != null) {
            username = usernameFromConfig;
        } else {
            username = "ejbca";
        }

        final String passwordFromArgs = parameters.get(PASSWORD_KEY);
        final String passwordFromConfig = EjbcaConfiguration.getCliDefaultPassword();

        if (passwordFromArgs != null) {
            password = passwordFromArgs;
        } else if (passwordFromConfig != null) {
            password = passwordFromConfig;
        } else {
            password = "ejbca";
        }
    }

    /**
     * This utility method gets an authenticated CliAuthenticationToken from the
     * authentication service.
     * 
     * Worth noting in this method is that the password is not sent as a
     * credential, because this would imply sending it (or its hash) in
     * cleartext over the network. Instead, it's only sent as part of a SHA1
     * hash (as part of the CliAuthenticationToken specification). Actual check
     * of the password's validity will formally occur at the first time that the
     * authentication token is checked for authorization.
     * 
     * Note also that the CliAuthenticationToken may only be used for a single
     * call via remote. I.e once it's passed through the network once, it's
     * invalid for further use.
     * 
     * 
     * @return a single use CliAuthenticationToken.
     */
    protected AuthenticationToken getAuthenticationToken() {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(username));

        AuthenticationSubject subject = new AuthenticationSubject(principals, null);

        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) EjbRemoteHelper.INSTANCE.getRemoteSession(
                CliAuthenticationProviderSessionRemote.class).authenticate(subject);
        // Set hashed value anew in order to send back
        if (authenticationToken == null) {
            throw new CliAuthenticationFailedException("Authentication failed. Username or password were not correct.");
        } else {
            authenticationToken.setSha1HashFromCleartextPassword(password);
            return authenticationToken;
        }
    }

    protected static ValueFoundResponse getValueFoundResponse(ValueFoundResponse defaultResponse) {
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        try {
            System.out.print(ValueFoundResponse.getQueryText() + " [default=" + defaultResponse.getResponse().toUpperCase() + "] ");
            System.out.flush();

            String input = bufferedReader.readLine();
            if (input.isEmpty()) {
                return defaultResponse;
            } else {
                ValueFoundResponse result = ValueFoundResponse.getResponseFromInput(input);
                if (result == null) {
                    System.out.println("Input not recognized: '" + input + "'");
                    return getValueFoundResponse(defaultResponse);
                } else {
                    return result;
                }
            }
        } catch (IOException e) {
            throw new RuntimeException("Unknown IOException occurred.", e);
        }
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
    
    @Override
    public  final void execute(String... arguments) throws IOException {
        Map<String, String> parameters = parameterHandler.parseParameters(this, arguments);
        if(parameters == null) {
            //Parameters couldn't be parsed, but this should already be handled. 
            return;
        }
        handleUserPasswordParams(parameters);
        execute(parameters);
    }
    
    /**
     * Execute commands on a local level, sans boilerplate code
     * 
     * @param parameters a map of the parameters. 
     * @throws IOException  
     */
    protected abstract void execute(Map<String, String> parameters) throws IOException;
    
    protected void registerParameter(Parameter parameter) {
        parameterHandler.registerParameter(parameter);
    }
    
    /**
     * Register parameters general for all commands.
     * 
     * @param parameterHandler the parameter handler to register the arguments with
     */
    private void registerDefaultParameters() {
        final String usernameInstruction = "A user name, if required.";
        final String passwordInstruction = "A password, if required.";
        this.registerParameter(new Parameter(CommandBase.USERNAME_KEY, "Username", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                usernameInstruction));
        this.registerParameter(new Parameter(CommandBase.PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.PASSWORD,
                passwordInstruction));
    }

    public abstract String getFullHelpText();
    
    public abstract String getImplementationName();
}
