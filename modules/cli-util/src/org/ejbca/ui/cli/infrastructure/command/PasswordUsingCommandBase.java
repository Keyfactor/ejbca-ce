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
import java.io.FileReader;
import java.io.IOException;
import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.authentication.cli.exception.CliAuthenticationFailedException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.CliUsernameException;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterHandler;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * @version $Id$
 *
 */
public abstract class PasswordUsingCommandBase extends CommandBase {

    private static final Logger log = Logger.getLogger(PasswordUsingCommandBase.class);

    public static final String USERNAME_KEY = "-u";
    public static final String PASSWORD_PROMPT_KEY = "-p";
    public static final String PASSWORD_KEY = "--clipassword";

    private static final String PASSWORD_MAN_TEXT = "Use the syntax " + USERNAME_KEY + " <username> " + PASSWORD_KEY
            + "=<password> to specify password explicitly or " + USERNAME_KEY + " <username> " + PASSWORD_PROMPT_KEY + " to prompt";

    private String password = null;
    private String username = null;

    {
        registerDefaultParameters();
    }

    /**
     * Register parameters general for all commands.
     * 
     * @param parameterHandler the parameter handler to register the arguments with
     */
    private void registerDefaultParameters() {
        this.registerParameter(new Parameter(USERNAME_KEY, "CLI Username", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Username for the CLI user, if required."));
        this.registerParameter(new Parameter(PASSWORD_KEY, "CLI Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Set the password explicitely in the command line with " + PASSWORD_KEY + "=<password>"));
        this.registerParameter(new Parameter(PASSWORD_PROMPT_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.PASSWORD,
                "Set this flag to be prompted for the username password"));
    }


    /**
     * Extracts the password and username arguments from the parameters map. 
     * 
     * @param parameters
     *            the map of parameters
     * @return A defensive copy, sans password parameters
     *            
     * @throws CliUsernameException If no username was supplied, and the default user is disabled.
     * @throws CliAuthenticationFailedException for any password related issues
     */
    private ParameterContainer stripUsernameAndPasswordFromParameters(ParameterContainer parameters) throws CliUsernameException,
            CliAuthenticationFailedException {
        GlobalConfigurationSessionRemote gcsession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        if (gcsession == null) {
            throw new CliAuthenticationFailedException("Can not get configuration from server. Is server started and communication working?");
        }
        GlobalConfiguration configuration = (GlobalConfiguration) gcsession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);

        ParameterContainer defensiveCopy = new ParameterContainer(parameters);

        username = parameters.get(USERNAME_KEY);
        if (username != null) {
            defensiveCopy.remove(USERNAME_KEY);
        }
        if(parameters.containsKey(PASSWORD_KEY)) {
            password = parameters.get(PASSWORD_KEY);
            defensiveCopy.remove(PASSWORD_KEY);
            if (password.startsWith("file:") && (password.length() > 5)) {
                final String fileName = password.substring(5);
                // Read the password file and just take the first line as being the password
                try {
                    BufferedReader br = new BufferedReader(new FileReader(fileName));
                    password = br.readLine();
                    br.close();
                    if (password != null) {
                        // Trim it, it's so easy for people to include spaces after a line, and a password should never end with a space
                        password = password.trim();
                    }
                    if ((password == null) || (password.length() == 0)) {
                        log.error("File '" + fileName + "' does not contain any lines.");
                        throw new CliAuthenticationFailedException("File '" + fileName + "' does not contain any lines.");
                    }
                } catch (IOException e) {
                    throw new CliAuthenticationFailedException("File '" + fileName + "' can not be read: " + e.getMessage());
                }
            }
        } else if (parameters.containsKey(PASSWORD_PROMPT_KEY)) {
            password = parameters.get(PASSWORD_PROMPT_KEY);
            defensiveCopy.remove(PASSWORD_PROMPT_KEY);
        }
        boolean defaultUserEnabled = configuration.getEnableCommandLineInterfaceDefaultUser();
        if ((username == null || password == null)) {
            if (defaultUserEnabled) {
                if (username == null) {
                    username = EjbcaConfiguration.getCliDefaultUser();
                }
                if (password == null) {
                    password = EjbcaConfiguration.getCliDefaultPassword();
                }
            } else {
                log.info("No CLI user was supplied, and use of the default CLI user is disabled.");
                throw new CliUsernameException("No CLI user was supplied, and use of the default CLI user is disabled.");
            }
        } else if (username.equals(EjbcaConfiguration.getCliDefaultUser()) && !defaultUserEnabled) {
            log.info("CLI authentication using default user is disabled.");
            log.info(PASSWORD_MAN_TEXT);
            throw new CliAuthenticationFailedException("CLI authentication using default user is disabled.");
        }

        if (!EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).existsUser(username)) {
            //We only check for username here, but it's needless to give too much info. 
            log.info("CLI authentication failed. The user '" + username + "' with the given password does not exist.");
            throw new CliAuthenticationFailedException("Authentication failed. User " + username + " not exist.");
        }
        return defensiveCopy;
    }

    @Override
    public CommandResult execute(String... arguments) {
        GlobalConfigurationSessionRemote gcsession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
        if (gcsession == null) {
            log.error("ERROR: Can not get configuration from server. Is server started and communication working?");
            return CommandResult.CLI_FAILURE;
        }
        GlobalConfiguration configuration = (GlobalConfiguration) gcsession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        //Check if ClI is enabled
        if (!configuration.getEnableCommandLineInterface()) {
            log.error("ERROR: Command Line Interface is disabled");
            return CommandResult.CLI_FAILURE;
        }
        //Check this before parsing so that user doesn't have to enter CLI password for a nonfunctional command
        boolean passwordPromt = false;
        boolean passwordSet = false;
        for(String argument : arguments) {
            if(argument.equals(PASSWORD_PROMPT_KEY)) {
                passwordPromt = true;
            } else if(argument.startsWith(PASSWORD_KEY)) {
                passwordSet = true;
            }
        }
        if (passwordPromt && passwordSet) {
            //Can't do both...
            log.error("Can't define both " + PASSWORD_KEY + " and specify a prompt (" + PASSWORD_PROMPT_KEY + ")");
            return CommandResult.CLI_FAILURE;
        }
        
        try {
            ParameterContainer parameters = parameterHandler.parseParameters(arguments);
            if(parameters == null) {
                //Parameters couldn't be parsed, but this should already be handled. 
                return CommandResult.CLI_FAILURE;
            }
            
            ParameterContainer strippedParameters = stripUsernameAndPasswordFromParameters(parameters);
            if (getAuthenticationToken() == null) {
                log.error("ERROR: username/password not found.");
                log.error(PASSWORD_MAN_TEXT);
                return CommandResult.AUTHORIZATION_FAILURE;
            }
            if (strippedParameters.containsKey(ParameterHandler.HELP_KEY)) {
                printManPage();
                return CommandResult.SUCCESS;
            } else {
                return execute(strippedParameters);
            }
        } catch (CliUsernameException e) {
            log.error("ERROR: " + e.getMessage());
            log.error(PASSWORD_MAN_TEXT);
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CliAuthenticationFailedException e) {
            log.error("ERROR: " + e.getMessage());
            log.error(PASSWORD_MAN_TEXT);
            return CommandResult.AUTHORIZATION_FAILURE;
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
     * @throws CliAuthenticationFailedException if authentication fails
     */
    protected AuthenticationToken getAuthenticationToken() {
        Set<Principal> principals = new HashSet<Principal>();
        principals.add(new UsernamePrincipal(username));

        AuthenticationSubject subject = new AuthenticationSubject(principals, null);

        CliAuthenticationToken authenticationToken = (CliAuthenticationToken) EjbRemoteHelper.INSTANCE.getRemoteSession(
                CliAuthenticationProviderSessionRemote.class).authenticate(subject);       
        if (authenticationToken == null) {
            return null;
        } else {
            // Set hashed value anew in order to send back
            authenticationToken.setSha1HashFromCleartextPassword(password);
            return authenticationToken;
        }
    }

}
