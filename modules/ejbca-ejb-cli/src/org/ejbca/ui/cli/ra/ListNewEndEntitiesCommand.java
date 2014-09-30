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
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * List end entities with status NEW in the database.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class ListNewEndEntitiesCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(ListNewEndEntitiesCommand.class);

    private static final String COMMAND = "listnewendentities";
    private static final String OLD_COMMAND = "listnewusers";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        for (EndEntityInformation data : EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                getAuthenticationToken(), EndEntityConstants.STATUS_NEW)) {
            getLogger().info(
                    "New end entity: " + data.getUsername() + ", \"" + data.getDN() + "\", \"" + data.getSubjectAltName() + "\", " + data.getEmail()
                            + ", " + data.getStatus() + ", " + data.getType().getHexValue() + ", " + data.getTokenType());
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "List end entities with status 'NEW'";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
