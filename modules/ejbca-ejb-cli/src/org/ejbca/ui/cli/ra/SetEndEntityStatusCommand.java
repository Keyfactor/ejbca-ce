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

import java.util.HashSet;
import java.util.Set;

import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes status for an end entity in the database, status is defined in
 * org.cesecore.certificates.endentity.EndEntityConstants
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class SetEndEntityStatusCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(SetEndEntityStatusCommand.class);

    private static final String COMMAND = "setendentitystatus";
    private static final String OLD_COMMAND = "setuserstatus";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    private static final String USERNAME_KEY = "--username";
    private static final String STATUS_KEY = "-S";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity."));
        registerParameter(new Parameter(STATUS_KEY, "Status", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Status: NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; HISTORICAL=50"));
    }

    @Override
    public Set<String> getMainCommandAliases() {
        return ALIASES;
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String username = parameters.get(USERNAME_KEY);
        int status;
        try {
            status = Integer.parseInt(parameters.get(STATUS_KEY));
        } catch (NumberFormatException e) {
            log.error("ERROR: " + parameters.get(STATUS_KEY) + " was not a number.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAuthenticationToken(), username,
                    status, 0);
            getLogger().info("New status for end entity " + username + " is " + status);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to change end entity.");
        }  catch (WaitingForApprovalException e) {
            getLogger().info("Status change request has been sent for approval.");
        } catch (FinderException e) {
            log.error("ERROR: " + e.getMessage());
        } catch (ApprovalException e) {
            getLogger().error("Status change already requested.");
        } 
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Change status for an end entity";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + ".\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }

}
