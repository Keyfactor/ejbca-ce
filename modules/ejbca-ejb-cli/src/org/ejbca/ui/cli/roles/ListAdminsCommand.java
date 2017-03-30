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

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
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
        final String roleName = parameters.get(ROLE_NAME_KEY);
        final Role role;
        try {
            role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getRole(getAuthenticationToken(), null, roleName);
        } catch (AuthorizationDeniedException e1) {
            getLogger().error("Not authorizied to role '" + roleName + "'.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        if (role == null) {
            getLogger().error("No such role '" + roleName + "'.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final List<RoleMember> roleMembers;
        try {
            roleMembers = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class).getRoleMembersByRoleId(
                    getAuthenticationToken(), role.getRoleId());
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorizied to members of role '" + roleName + "'.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        Collections.sort(roleMembers, new Comparator<RoleMember>(){
            @Override
            public int compare(final RoleMember roleMember1, final RoleMember roleMember2) {
                final int compareTokenType = roleMember1.getTokenType().compareTo(roleMember2.getTokenType());
                if (compareTokenType != 0) {
                    return compareTokenType;
                }
                final int compareTokenMatchKey = Integer.valueOf(roleMember1.getTokenMatchKey()).compareTo(Integer.valueOf(roleMember2.getTokenMatchKey()));
                if (compareTokenMatchKey != 0) {
                    return compareTokenMatchKey;
                }
                final int compareTokenMatchValue = roleMember1.getTokenMatchValue().compareTo(roleMember1.getTokenMatchValue());
                return compareTokenMatchValue;
            }}
        );
        for (final RoleMember roleMember : roleMembers) {
            String caName;
            if (roleMember.getTokenIssuerId() == RoleMember.NO_ISSUER) {
                caName = "[Admin unbound to CA]";
            } else {
                try {
                    final CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                            roleMember.getTokenIssuerId());
                    caName = "'" + info.getName() +  "'";
                } catch (CADoesntExistsException e) {
                    caName = "[Unknown CA with ID " + roleMember.getTokenIssuerId() + "]";
                } catch (AuthorizationDeniedException e) {
                    caName = "[(Name redacted) CA with ID " + roleMember.getTokenIssuerId() + "]";
                }
            }
            final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(roleMember.getTokenType(),
                    roleMember.getTokenMatchKey());
            final AccessMatchType accessMatchType = roleMember.getAccessMatchType();
            final String tokenMatchValue = roleMember.getTokenMatchValue();
            final String description = roleMember.getDescription();
            getLogger().info( caName + " " + accessMatchValue + " " + accessMatchType + " \"" + tokenMatchValue + "\"" + " \"" + description + "\"");
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
