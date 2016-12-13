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

package org.ejbca.ui.cli.ra;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Set the clear text password for an end entity in the database.  Clear text passwords are used for batch
 * generation of keystores (pkcs12/pem).
 *
 * @version $Id$
 */
public class SetCleartextPasswordCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(SetCleartextPasswordCommand.class);

    private static final String USERNAME_KEY = "--username";
    private static final String PASSWORD_KEY = "--password";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity."));
        registerParameter(new Parameter(PASSWORD_KEY, "Password", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "New password for the end entity. Leaving out password will prompt for it."));
    }

    @Override
    public String getMainCommand() {
        return "setclearpwd";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String username = parameters.get(USERNAME_KEY);
        String password = parameters.get(PASSWORD_KEY);
        if(password == null) {
            log.info("Enter password: ");
            // Read the password, but mask it so we don't display it on the console
            password = String.valueOf(System.console().readPassword());
        }
        getLogger().info("Setting clear text password for user " + username);
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setClearTextPassword(getAuthenticationToken(),
                    username, password);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to modify end entity.");
        } catch (UserDoesntFullfillEndEntityProfile e) {
            getLogger().error("Given userdata doesn't fullfill end entity profile. : " + e.getMessage());
        } catch (NoSuchEndEntityException e) {
            getLogger().error("End entity with username '" + username + "' does not exist.");
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Set a clear text password for an end entity for batch generation";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }

}
