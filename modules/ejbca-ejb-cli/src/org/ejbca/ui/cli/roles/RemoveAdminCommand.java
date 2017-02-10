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

import java.util.ArrayList;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Removes an admin
 * @version $Id$
 */
public class RemoveAdminCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(RemoveAdminCommand.class);

    private static final String ROLE_NAME_KEY = "--role";
    private static final String CA_NAME_KEY = "--caname";
    private static final String MATCH_WITH_KEY = "--with";
    private static final String MATCH_TYPE_KEY = "--type";
    private static final String MATCH_VALUE_KEY = "--value";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to list rules of."));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the issuing CA"));
        registerParameter(new Parameter(MATCH_WITH_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The MatchWith Value"));
        registerParameter(new Parameter(MATCH_TYPE_KEY, "Type", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The MatchType"));
        registerParameter(new Parameter(MATCH_VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The value to match against."));
    }

    @Override
    public String getMainCommand() {
        return "removeadmin";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String roleName = parameters.get(ROLE_NAME_KEY);
        AdminGroupData role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class).findRole(roleName);
        if (role == null) {
            getLogger().error("No such role \"" + roleName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        String caName = parameters.get(CA_NAME_KEY);
        CAInfo caInfo;
        try {
            caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
        } catch (CADoesntExistsException e) {
            getLogger().error("No such CA \"" + caName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            getLogger().error("CLI user not authorized to CA " + caName + "\".");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        if (caInfo == null) {
            getLogger().error("No such CA \"" + caName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.lookupMatchValueFromTokenTypeAndName(
                X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, parameters.get(MATCH_WITH_KEY));
        if (matchWith == null) {
            getLogger().error("No such thing to match with as \"" + parameters.get(MATCH_WITH_KEY) + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        AccessMatchType matchType = AccessMatchType.matchFromName(parameters.get(MATCH_TYPE_KEY));
        if (matchType == null) {
            getLogger().error("No such type to match with as \"" + parameters.get(MATCH_TYPE_KEY) + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        String matchValue = parameters.get(MATCH_VALUE_KEY);
        int caId;
        try {
            caId = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName).getCAId();
        } catch (CADoesntExistsException e) {
            getLogger().error("No such CA \"" + caName + "\".");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            getLogger().error("CLI user not authorized to CA " + caName + "\".");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        AccessUserAspectData accessUserAspectData = new AccessUserAspectData(roleName, caId, matchWith, matchType, matchValue);

        for (AccessUserAspectData currentAdminEntity : role.getAccessUsers().values()) {
            if (currentAdminEntity.getMatchValue().equals(accessUserAspectData.getMatchValue())
                    && currentAdminEntity.getMatchWith() == accessUserAspectData.getMatchWith()
                    && currentAdminEntity.getMatchType() == accessUserAspectData.getMatchType()
                    && currentAdminEntity.getCaId().equals(accessUserAspectData.getCaId())) {
                Collection<AccessUserAspectData> adminEntities = new ArrayList<AccessUserAspectData>();
                adminEntities.add(accessUserAspectData);

                try {
                    EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class).removeSubjectsFromRole(getAuthenticationToken(),
                            role, adminEntities);
                    log.info("Removed admin/subject: " + "\"" + caName + "\" " + matchWith + " " + matchType + " \"" + matchValue + "\" from role " + roleName);
                } catch (RoleNotFoundException e) {
                    throw new IllegalStateException("Previously found role " + role.getRoleName() + " was not found.");
                } catch (AuthorizationDeniedException e) {
                    getLogger().error("CLI user not authorized to role " + role.getRoleName() + "\".");
                    return CommandResult.AUTHORIZATION_FAILURE;
                }

               return CommandResult.SUCCESS;
            }
        }
        getLogger().info("Could not find any matching admin in role \"" + roleName + "\".");
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Removes an admin";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
