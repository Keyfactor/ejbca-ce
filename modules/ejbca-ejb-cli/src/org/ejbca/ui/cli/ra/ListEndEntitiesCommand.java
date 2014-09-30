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

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * List end entities with specified status in the database.
 *
 * @version $Id$
 *
 * @see org.ejbca.core.ejb.ra.UserDataLocal
 */
public class ListEndEntitiesCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(ListEndEntitiesCommand.class);

    private static final String COMMAND = "listendentities";
    private static final String OLD_COMMAND = "listusers";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    private static final String STATUS_KEY = "-S";

    {
        registerParameter(new Parameter(STATUS_KEY, "Status", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Status: ANY=00; NEW=10; FAILED=11; INITIALIZED=20; INPROCESS=30; GENERATED=40; REVOKED=50; HISTORICAL=60; KEYRECOVERY=70"));
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

        int status;
        try {
            status = Integer.parseInt(parameters.get(STATUS_KEY));
        } catch (NumberFormatException e) {
            log.error("ERROR: " + parameters.get(STATUS_KEY) + " was not a number.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        Collection<EndEntityInformation> coll = null;
        if (status == 0) {
            coll = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(),
                    EndEntityConstants.STATUS_NEW);
            coll.addAll(EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                    getAuthenticationToken(), EndEntityConstants.STATUS_FAILED));
            coll.addAll(EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                    getAuthenticationToken(), EndEntityConstants.STATUS_INITIALIZED));
            coll.addAll(EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                    getAuthenticationToken(), EndEntityConstants.STATUS_INPROCESS));
            coll.addAll(EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                    getAuthenticationToken(), EndEntityConstants.STATUS_GENERATED));
            coll.addAll(EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(
                    getAuthenticationToken(), EndEntityConstants.STATUS_REVOKED));
        } else {
            coll = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).findAllUsersByStatus(getAuthenticationToken(),
                    status);
        }
        if (coll.size() == 0) {
            getLogger().info("No end entities with status " + status + " found.");
        } else {
            for (EndEntityInformation endEntityInformation : coll) {
                getLogger().info(
                        "End Entity: " + endEntityInformation.getUsername() + ", \"" + endEntityInformation.getDN() + "\", \""
                                + endEntityInformation.getSubjectAltName() + "\", " + endEntityInformation.getEmail() + ", "
                                + endEntityInformation.getStatus() + ", " + endEntityInformation.getType().getHexValue() + ", "
                                + endEntityInformation.getTokenType() + ", " + endEntityInformation.getHardTokenIssuerId());
            }
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "List end entities with a specified status.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        sb.append("Outputs comma separated items: username, subjectDN, subjectAltName, email, status, type, tokenType, hardTokenIssuerId.\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }
}
