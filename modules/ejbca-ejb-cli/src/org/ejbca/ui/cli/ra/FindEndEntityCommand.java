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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Find details of an end entity in the database.
 *
 * @version $Id$
 */
public class FindEndEntityCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(FindEndEntityCommand.class);

    private static final String COMMAND = "findendentity";
    private static final String OLD_COMMAND = "finduser";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    private static final String USERNAME_KEY = "--username";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity to delete."));
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
        try {
            EndEntityInformation data = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                    getAuthenticationToken(), username);
            if (data != null) {
                getLogger().info("Found end entity:");
                getLogger().info("Username: " + data.getUsername());
                getLogger().info("Password: " + (data.getPassword() != null ? data.getPassword() : "<hidden>"));
                getLogger().info("DN: \"" + data.getDN() + "\"");
                getLogger().info("Alt Name: \"" + data.getSubjectAltName() + "\"");
                ExtendedInformation ei = data.getExtendedinformation();
                getLogger().info("Directory Attributes: \"" + (ei != null ? ei.getSubjectDirectoryAttributes() : "") + "\"");
                getLogger().info("E-Mail: " + data.getEmail());
                getLogger().info("Status: " + data.getStatus());
                getLogger().info("Type: " + data.getType().getHexValue());
                getLogger().info("Token Type: " + data.getTokenType());
                getLogger().info("End Entity Profile ID: " + data.getEndEntityProfileId());
                getLogger().info("Certificate Profile ID: " + data.getCertificateProfileId());
                getLogger().info("Hard Token Issuer ID: " + data.getHardTokenIssuerId());
                getLogger().info("Created: " + data.getTimeCreated());
                getLogger().info("Modified: " + data.getTimeModified());
                return CommandResult.SUCCESS;
            } else {
                getLogger().error("End entity '" + username + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().error("ERROR: Not authorized to view end entity.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Find and show details of an end entity";
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
