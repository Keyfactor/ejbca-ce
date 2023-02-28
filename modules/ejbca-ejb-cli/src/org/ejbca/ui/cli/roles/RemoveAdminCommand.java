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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
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
 * Removes an admin
 */
public class RemoveAdminCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(RemoveAdminCommand.class);

    private static final String ROLE_NAME_KEY = "--role";
    private static final String CA_NAME_KEY = "--caname";
    private static final String MATCH_WITH_KEY = "--with";
    private static final String MATCH_TYPE_KEY = "--type";
    private static final String MATCH_VALUE_KEY = "--value";
    private static final String ROLE_NAMESPACE_KEY = "--namespace";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to list rules of."));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the issuing CA"));
        registerParameter(new Parameter(MATCH_WITH_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The MatchWith Value"));
        registerParameter(new Parameter(MATCH_TYPE_KEY, "Type", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(Deprected) Match operator type. Kept to prevent legacy scripts from breaking. Currently implied by " + MATCH_WITH_KEY +" switch."));
        registerParameter(new Parameter(MATCH_VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The value to match against."));
        registerParameter(new Parameter(ROLE_NAMESPACE_KEY, "Role Namespace", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The namespace the role belongs to."));
    }

    @Override
    public String getMainCommand() {
        return "removeadmin";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String roleName = parameters.get(ROLE_NAME_KEY);
        final String namespace = parameters.get(ROLE_NAMESPACE_KEY);
        final Role role;
        try {
            role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getRole(getAuthenticationToken(), namespace, roleName);
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to role " + super.getFullRoleName(namespace, roleName) + ".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (role == null) {
            getLogger().error("No such role " + super.getFullRoleName(namespace, roleName) + ".");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final String matchWithKeyParam = parameters.get(MATCH_WITH_KEY);
        if (StringUtils.isEmpty(matchWithKeyParam)) {
            getLogger().error("No such thing to match with as '" + parameters.get(MATCH_WITH_KEY) + "'.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final String tokenType;
        final String matchWithKey;
        final String[] matchWithKeySplit = matchWithKeyParam.split(":");
        if (matchWithKeySplit.length == 1) {
            tokenType = X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE;
            matchWithKey = matchWithKeySplit[0];
            getLogger().info("Match TokenType is assumed to be '" + tokenType + "'.");
        } else {
            tokenType = matchWithKeySplit[0];
            matchWithKey = matchWithKeySplit[1];
            final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
            if (authenticationTokenMetaData == null || !authenticationTokenMetaData.isUserConfigurable()) {
                getLogger().error("TokenType '" + tokenType + "' is not configurable.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        final int tokenIssuerId;
        final String caName;
        if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType)) {
            final String caNameParam = parameters.get(CA_NAME_KEY);
            final CAInfo caInfo;
            try {
                caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caNameParam);
            }  catch (AuthorizationDeniedException e) {
                getLogger().error("CLI user not authorized to CA");
                return CommandResult.AUTHORIZATION_FAILURE;
            }
            if (caInfo == null) {
                getLogger().error("No such CA '" + caNameParam + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            tokenIssuerId = caInfo.getCAId();
            caName = caInfo.getName();
        } else {
            // To be backwards compatible with existing scripts in the wild, we will still have to require parameter but we ignore the value if is unused
            //getLogger().info("Ignoring mandatory '" + CA_NAME_KEY + "' parameter value for the selected Token Type '" + tokenType + "'.");
            tokenIssuerId = RoleMember.NO_ISSUER;
            caName = "-";
        }
        final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.lookupMatchValueFromTokenTypeAndName(tokenType, matchWithKey);
        if (accessMatchValue == null) {
            getLogger().error("No such thing to match with as '" + matchWithKey + "'.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final String accessMatchTypeParam = parameters.get(MATCH_TYPE_KEY);
        final AccessMatchType accessMatchType;
        if (accessMatchTypeParam==null) {
            if (accessMatchValue.getAvailableAccessMatchTypes().isEmpty()) {
                accessMatchType = AccessMatchType.TYPE_UNUSED;
            } else {
                accessMatchType = accessMatchValue.getAvailableAccessMatchTypes().get(0);
            }
            getLogger().info("Using '"+accessMatchType+"' implied by '" + accessMatchValue + "'.");
        } else {
            accessMatchType = AccessMatchType.matchFromName(parameters.get(MATCH_TYPE_KEY));
            if (accessMatchType == null) {
                getLogger().error("No such type to match with as '" + parameters.get(MATCH_TYPE_KEY) + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        final String tokenMatchValue = parameters.get(MATCH_VALUE_KEY);
        final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
        try {
            boolean foundMatch = false;
            for (final RoleMember roleMember : roleMemberSession.getRoleMembersByRoleId(getAuthenticationToken(), role.getRoleId())) {
                if (tokenType.equals(roleMember.getTokenType()) &&
                        tokenIssuerId == roleMember.getTokenIssuerId() &&
                        accessMatchValue.getNumericValue()==roleMember.getTokenMatchKey() &&
                        accessMatchType.getNumericValue()==roleMember.getTokenMatchOperator() &&
                        tokenMatchValue.equals(roleMember.getTokenMatchValue())) {
                    roleMemberSession.remove(getAuthenticationToken(), roleMember.getId());
                    foundMatch = true;
                    getLogger().info("Removed role member: " + "'" + caName + "' " + accessMatchValue + " " + accessMatchType + " '" +
                            tokenMatchValue + "' from role " + super.getFullRoleName(namespace, roleName));
                }
            }
            if (!foundMatch) {
                getLogger().info("Could not find any matching admin in role " + super.getFullRoleName(namespace, roleName) + ".");
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().info("Not authorized to members of role " + super.getFullRoleName(namespace, roleName) + ".");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
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
