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
import java.util.List;

import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authentication.tokens.AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.OAuth2AuthenticationTokenMetaData;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionRemote;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.StringTools;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Adds a role member.
 */
public class AddRoleMemberCommand extends BaseRolesCommand {

    private static final Logger log = Logger.getLogger(AddRoleMemberCommand.class);

    private static final String ROLE_NAME_KEY = "--role";
    private static final String CA_NAME_KEY = "--caname";
    private static final String PROVIDER_NAME_KEY = "--provider";
    private static final String MATCH_WITH_KEY = "--with";
    private static final String MATCH_TYPE_KEY = "--type";
    private static final String MATCH_VALUE_KEY = "--value";
    private static final String DESCRIPTION_KEY = "--description";
    private static final String ROLE_NAMESPACE_KEY = "--namespace";

    {
        registerParameter(new Parameter(ROLE_NAME_KEY, "Role Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Role to add admin to."));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of issuing CA. Set to empty string if not applicable"));
        registerParameter(new Parameter(MATCH_WITH_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The MatchWith Value"));
        registerParameter(new Parameter(MATCH_TYPE_KEY, "Type", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "(Ignored) Match operator type. Kept to prevent legacy scripts from breaking. Currently implied by " + MATCH_WITH_KEY +" switch."));
        registerParameter(new Parameter(MATCH_VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The value to match against."));
        registerParameter(new Parameter(DESCRIPTION_KEY, "Description", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "A human readable description of the role member."));
        registerParameter(new Parameter(ROLE_NAMESPACE_KEY, "Role Namespace", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The namespace the role belongs to."));
        registerParameter(new Parameter(PROVIDER_NAME_KEY, "OAuth Provider Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of OAuth Provider. Required for OAuth"));
    }

    @Override
    public String getMainCommand() {
        return "addrolemember";
    }

    @SuppressWarnings("unused")
    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String roleName = parameters.get(ROLE_NAME_KEY);
        final String namespace = parameters.get(ROLE_NAMESPACE_KEY);
        final Role role;
        try {
            role = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getRole(getAuthenticationToken(), namespace, roleName);
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to role " + super.getFullRoleName(namespace, roleName) + ".");
            return CommandResult.AUTHORIZATION_FAILURE;
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
        final int tokenProviderId;
        if (X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType)) {
            final String caName = parameters.get(CA_NAME_KEY);
            final CAInfo caInfo;
            try {
                caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
            }  catch (AuthorizationDeniedException e) {
                getLogger().error("CLI user not authorized to CA");
                return CommandResult.AUTHORIZATION_FAILURE;
            }
            if (caInfo == null) {
                getLogger().error("No such CA '" + caName + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            tokenIssuerId = caInfo.getCAId();
            tokenProviderId = RoleMember.NO_PROVIDER;
        } else if (OAuth2AuthenticationTokenMetaData.TOKEN_TYPE.equals(tokenType)) {
            final String providerLabel = parameters.get(PROVIDER_NAME_KEY);
            if (StringUtils.isEmpty(providerLabel)) {
                getLogger().error("--provider is required for this match value.");
                return CommandResult.CLI_FAILURE;
            }
            final OAuthConfiguration oauthConfig = (OAuthConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class).
                    getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
            if (oauthConfig == null || MapUtils.isEmpty((oauthConfig.getOauthKeys()))) {
                getLogger().error("No OAuth providers have been configured. Can't add role member.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            final OAuthKeyInfo oauthInfo = oauthConfig.getOauthKeyByLabel(providerLabel);
            if (oauthInfo == null) {
                getLogger().error("No such OAuth provider '" + providerLabel + "'.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            tokenProviderId = oauthInfo.getInternalId();
            // To be backwards compatible with existing scripts in the wild, we will still have to require the --caname parameter but we ignore the value if is unused
            tokenIssuerId = RoleMember.NO_ISSUER;
        } else {
            tokenIssuerId = RoleMember.NO_ISSUER;
            tokenProviderId = RoleMember.NO_PROVIDER;
        }
        final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.lookupMatchValueFromTokenTypeAndName(tokenType, matchWithKey);
        if (accessMatchValue == null) {
            getLogger().error("No such thing to match with as '" + parameters.get(MATCH_WITH_KEY) + "'.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final AccessMatchType accessMatchType;
        if (accessMatchValue.getAvailableAccessMatchTypes().isEmpty()) {
            accessMatchType = AccessMatchType.TYPE_UNUSED;
        } else {
            // Just grab the first one, since we according to ECA-3164 only will have a single allowed match operator for each match key
            accessMatchType = accessMatchValue.getAvailableAccessMatchTypes().get(0);
        }
        final String matchTypeParam = parameters.get(MATCH_TYPE_KEY);
        if (StringUtils.isNotEmpty(matchTypeParam)) {
            getLogger().info("Parameter " + MATCH_TYPE_KEY + " is ignored. " + MATCH_WITH_KEY + " value " + accessMatchValue.name() + " implies " + accessMatchType.name() + ".");
        }
        final String description = parameters.get(DESCRIPTION_KEY);
        
        String matchValue = null;
        if (accessMatchValue == X500PrincipalAccessMatchValue.WITH_SERIALNUMBER) {
           matchValue = StringTools.removeAllWhitespaceAndColon(parameters.get(MATCH_VALUE_KEY));   
        } else {
           matchValue = parameters.get(MATCH_VALUE_KEY);
        }  
                
        final RoleMember roleMember = new RoleMember(tokenType, tokenIssuerId, tokenProviderId, accessMatchValue.getNumericValue(), accessMatchType.getNumericValue(),
                matchValue , role.getRoleId(), description);
        try {
            final RoleMemberSessionRemote roleMemberSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleMemberSessionRemote.class);
            if (roleMemberExists(roleMember, roleMemberSession)) {
                getLogger().error(
                        "The role member " + roleMember.getTokenMatchValue() + " was not added because it already exists in the role " + roleName);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            roleMemberSession.persist(getAuthenticationToken(), roleMember);
            getLogger().info("Role member was successfully added.");
        } catch (AuthorizationDeniedException e) {
            getLogger().error("CLI user not authorized to edit role");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    private boolean roleMemberExists(final RoleMember roleMember, final RoleMemberSessionRemote roleMemberSession)
            throws AuthorizationDeniedException {
        return roleMemberSession.getRoleMembersByRoleId(getAuthenticationToken(), roleMember.getRoleId()).stream()
                .anyMatch(existingMember -> existingMember.isSameAs(roleMember));
    }
    
    @Override
    public String getCommandDescription() {
        return "Adds a member to a role.";
    }

    @Override
    public String getFullHelpText() {
        final StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + ".\n");
        final List<Role> roles = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleSessionRemote.class).getAuthorizedRoles(getAuthenticationToken());
        Collections.sort(roles);
        String availableRoles = "";
        for (final Role role : roles) {
            availableRoles += availableRoles.length() == 0 ? "" : ", ";
            availableRoles += "'" + super.getFullRoleName(role.getNameSpace(), role.getRoleName()) + "'";
        }
        sb.append("\nAvailable Roles: " + availableRoles + "\n");
        String availableCas = "";
        for (final String caName : EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaNames(getAuthenticationToken())) {
            availableCas += (availableCas.length() == 0 ? "" : ", ") + "" + caName + "";
        }
        sb.append("\nAvailable CAs: " + availableCas + "\n");
        sb.append("\nAvailable OAuth Providers: ");
        final OAuthConfiguration oauthConfig = (OAuthConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class).
                getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        if (oauthConfig == null || MapUtils.isEmpty((oauthConfig.getOauthKeys()))) {
            sb.append("<No providers configured>");
        } else {
            sb.append(String.join(", ", oauthConfig.getOauthKeys().keySet()));
        }
        sb.append("\n");
        String availableAccessMatchValues = "";
        for (final String tokenType : AccessMatchValueReverseLookupRegistry.INSTANCE.getAllTokenTypes()) {
            final AuthenticationTokenMetaData authenticationTokenMetaData = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(tokenType);
            if (authenticationTokenMetaData.isUserConfigurable()) {
                for (final String accessMatchValueName : authenticationTokenMetaData.getAccessMatchValueNameMap().keySet()) {
                    availableAccessMatchValues += (availableAccessMatchValues.isEmpty() ? "" : ", ") + tokenType + ":" + accessMatchValueName;
                }
            }
        }
        sb.append("\nMatch with is one of ('CertificateAuthenticationToken:' can be omitted): " + availableAccessMatchValues + "\n");
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
