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

package org.ejbca.ui.cli.roles;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Lists admins in a role
 * @version $Id$
 */
public class ListAdminsCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(ListAdminsCommand.class);

    private static final String ROLE_NAME_KEY = "--role";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to list admins of."));
    }

    @Override
    public String getMainCommand() {
        return "listadmins";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String roleName = parameters.get(ROLE_NAME_KEY);
        AdminGroupData role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName);
        if (role == null) {
            getLogger().error("No such role \"" + roleName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        for (AccessUserAspectData userAspect : role.getAccessUsers().values()) {
            String caName;
            try {
                CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                        userAspect.getCaId());
                caName = "\"" + info.getName() +  "\" ";
            } catch (CADoesntExistsException e) {
                if (userAspect.getCaId() == 0) {
                    //0 is reserved for internal use
                    caName = "[Admin unbound to CA] ";
                } else {
                    caName = "[Nonexistent CA with ID " + userAspect.getCaId() + "] ";
                }
            } catch (AuthorizationDeniedException e) {
                log.error("CLI user not authorized to CA with ID: " + userAspect.getCaId());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(userAspect.getTokenType(),
                    userAspect.getMatchWith());
            AccessMatchType matchType = userAspect.getMatchTypeAsType();
            String matchValue = userAspect.getMatchValue();
            getLogger().info( caName + matchWith + " " + matchType + " \"" + matchValue + "\"");
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Lists admins in a role.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        sb.append("Outputs fields: caName, matchWith, matchType, matchValue.\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
