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
package org.ejbca.core.ejb.authorization;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRulePlugin;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenMetaData;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * This session bean handles high level authorization system tasks.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AuthorizationSystemSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AuthorizationSystemSessionBean implements AuthorizationSystemSessionLocal, AuthorizationSystemSessionRemote {

    private static final Logger log = Logger.getLogger(AuthorizationSystemSessionBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleDataSessionLocal roleDataSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;
    @EJB
    private RoleMemberDataSessionLocal roleMemberDataSession;
    @EJB
    private UserDataSourceSessionLocal userDataSourceSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public Map<String,String> getAllResources(final AuthenticationToken authenticationToken, final boolean ignoreLimitations) {
        final Map<String,String> authorizedResources = new HashMap<>();
        try {
            final HashMap<String, Boolean> accessRules = authorizationSession.getAccessAvailableToAuthenticationToken(authenticationToken);
            for (final Entry<String,String> entry : getAllResources(ignoreLimitations).entrySet()) {
                if (AccessRulesHelper.hasAccessToResource(accessRules, entry.getKey())) {
                    authorizedResources.put(AccessRulesHelper.normalizeResource(entry.getKey()), AccessRulesHelper.normalizeResource(entry.getValue()));
                }
            }
        } catch (AuthenticationFailedException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to get resources due to authentication failure: " + e.getMessage());
            }
        }
        return authorizedResources;
    }

    @Override
    public Map<String,String> getAllResources(final boolean ignoreLimitations) {
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        final Map<Integer, String> eepIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        final Map<Integer, String> userDataSourceIdToNameMap = userDataSourceSession.getUserDataSourceIdToNameMap();
        final Map<Integer,String> cryptoTokenIdToNameMap = cryptoTokenSession.getCryptoTokenIdToNameMap();
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final boolean endEntityProfileLimitationsEnabled = ignoreLimitations || globalConfiguration.getEnableEndEntityProfileLimitations();
        final boolean hardTokenIssuingEnabled = ignoreLimitations || globalConfiguration.getIssueHardwareTokens();
        final boolean keyRecoveryEnabled = ignoreLimitations || globalConfiguration.getEnableKeyRecovery();
        final Map<String, Map<String,String>> categorizedAccessRules = getAllResourceAndResourceNamesByCategory(
                endEntityProfileLimitationsEnabled, hardTokenIssuingEnabled, keyRecoveryEnabled,
                Arrays.asList(EjbcaConfiguration.getCustomAvailableAccessRules()), eepIdToNameMap, userDataSourceIdToNameMap, cryptoTokenIdToNameMap, caIdToNameMap);
        final Map<String,String> ret = new HashMap<>();
        for (final Map<String,String> acessRuleMap : categorizedAccessRules.values()) {
            ret.putAll(acessRuleMap);
        }
        return ret;
    }

    @Override
    public Map<String,Map<String,String>> getAllResourceAndResourceNamesByCategory() {
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        final Map<Integer, String> eepIdToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        final Map<Integer, String> userDataSourceIdToNameMap = userDataSourceSession.getUserDataSourceIdToNameMap();
        final Map<Integer,String> cryptoTokenIdToNameMap = cryptoTokenSession.getCryptoTokenIdToNameMap();
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final boolean endEntityProfileLimitationsEnabled = globalConfiguration.getEnableEndEntityProfileLimitations();
        final boolean hardTokenIssuingEnabled = globalConfiguration.getIssueHardwareTokens();
        final boolean keyRecoveryEnabled = globalConfiguration.getEnableKeyRecovery();
        return getAllResourceAndResourceNamesByCategory(
                endEntityProfileLimitationsEnabled, hardTokenIssuingEnabled, keyRecoveryEnabled,
                Arrays.asList(EjbcaConfiguration.getCustomAvailableAccessRules()), eepIdToNameMap, userDataSourceIdToNameMap, cryptoTokenIdToNameMap, caIdToNameMap);
    }

    private Map<String,Map<String,String>> getAllResourceAndResourceNamesByCategory(boolean endEntityProfileLimitationsEnabled,
            boolean hardTokenIssuingEnabled, boolean keyRecoveryEnabled,
            Collection<String> customAccessRules, Map<Integer,String> eepIdToNameMap, Map<Integer, String> userDataSourceIdToNameMap,
            Map<Integer,String> cryptoTokenIdToNameMap, Map<Integer,String> caIdToNameMap) {
        final Map<String,Map<String,String>> ret = new LinkedHashMap<>();
        // Role based access rules
        final Map<String,String> accessRulesRoleBased = new LinkedHashMap<>();
        accessRulesRoleBased.put(AccessRulesConstants.ROLE_PUBLICWEBUSER, AccessRulesConstants.ROLE_PUBLICWEBUSER);
        accessRulesRoleBased.put(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRulesConstants.ROLE_ADMINISTRATOR);
        accessRulesRoleBased.put(StandardRules.ROLE_ROOT.resource(), StandardRules.ROLE_ROOT.resource());
        ret.put("ROLEBASEDACCESSRULES", accessRulesRoleBased);
        // Standard rules (including custom access rules)
        final Map<String,String> accessRulesRegular = new LinkedHashMap<>();
        for (final String resource : AccessRulesConstants.STANDARDREGULARACCESSRULES) {
            accessRulesRegular.put(resource, resource);
        }
        if (hardTokenIssuingEnabled) {
            for (final String resource : AccessRulesConstants.HARDTOKENACCESSRULES) {
                accessRulesRegular.put(resource, resource);
            }
            accessRulesRegular.put(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, AccessRulesConstants.REGULAR_VIEWHARDTOKENS);
            accessRulesRegular.put(AccessRulesConstants.REGULAR_VIEWPUKS, AccessRulesConstants.REGULAR_VIEWPUKS);
        }
        if (keyRecoveryEnabled) {
            accessRulesRegular.put(AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRulesConstants.REGULAR_KEYRECOVERY);
        }
        for (final String resource : customAccessRules) {
            if (!StringUtils.isEmpty(resource.trim())) {
                accessRulesRegular.put(resource.trim(), resource.trim());
            }
        }
        ret.put("REGULARACCESSRULES", accessRulesRegular);
        // Insert CA access rules
        final Map<String,String> accessRulesCaAccess = new LinkedHashMap<>();
        accessRulesCaAccess.put(StandardRules.CAACCESSBASE.resource(), StandardRules.CAACCESSBASE.resource());
        for (final int caId : caIdToNameMap.keySet()) {
            final String caName = caIdToNameMap.get(caId);
            accessRulesCaAccess.put(StandardRules.CAACCESS.resource() + caId, StandardRules.CAACCESS.resource() + caName);
        }
        ret.put("CAACCESSRULES", accessRulesCaAccess);
        // End entity profile rules
        if (endEntityProfileLimitationsEnabled) {
            final Map<String,String> accessRulesEepAccess = new LinkedHashMap<>();
            // Add most basic rule if authorized to it.
            accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRulesConstants.ENDENTITYPROFILEBASE);
            // Add all authorized End Entity Profiles
            for (final int eepId : eepIdToNameMap.keySet()) {
                final String eepName = eepIdToNameMap.get(eepId);
                // Administrator is authorized to this End Entity Profile, add it.
                accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId, AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepName);
                for (final String subResource : AccessRulesConstants.ENDENTITYPROFILE_ENDINGS) {
                    accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + subResource,
                            AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepName + subResource);
                }
                if (hardTokenIssuingEnabled) {
                    accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.HARDTOKEN_RIGHTS,
                            AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepName + AccessRulesConstants.HARDTOKEN_RIGHTS);
                    accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS,
                            AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepName + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
                }
                if (keyRecoveryEnabled) {
                    accessRulesEepAccess.put(AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepId + AccessRulesConstants.KEYRECOVERY_RIGHTS,
                            AccessRulesConstants.ENDENTITYPROFILEPREFIX + eepName + AccessRulesConstants.KEYRECOVERY_RIGHTS);
                }
            }
            ret.put("ENDENTITYPROFILEACCESSR", accessRulesEepAccess);
        }
        // Crypto token rules
        final Map<String,String> accessRulesCtAccess = new LinkedHashMap<>();
        for (final CryptoTokenRules rule : CryptoTokenRules.values()) {
            accessRulesCtAccess.put(rule.resource(), rule.resource());
        }
        for (final int cryptoTokenId : cryptoTokenIdToNameMap.keySet()) {
            final String cryptoTokenName = cryptoTokenIdToNameMap.get(cryptoTokenId);
            for (final CryptoTokenRules rule : CryptoTokenRules.values()) {
                if (!rule.equals(CryptoTokenRules.BASE) && !rule.equals(CryptoTokenRules.MODIFY_CRYPTOTOKEN) && !rule.equals(CryptoTokenRules.DELETE_CRYPTOTOKEN)) {
                    accessRulesCtAccess.put(rule.resource() + "/" + cryptoTokenId, rule.resource() + "/" + cryptoTokenName);
                }
            }
        }
        ret.put("CRYPTOTOKENACCESSRULES", accessRulesCtAccess);
        // Insert User data source access rules
        final Map<String,String> accessRulesUdsAccess = new LinkedHashMap<>();
        accessRulesUdsAccess.put(AccessRulesConstants.USERDATASOURCEBASE, AccessRulesConstants.USERDATASOURCEBASE);
        for (final int userDataSourceId : userDataSourceIdToNameMap.keySet()) {
            final String userDataSourceName = userDataSourceIdToNameMap.get(userDataSourceId);
            accessRulesUdsAccess.put(AccessRulesConstants.USERDATASOURCEPREFIX + userDataSourceId + AccessRulesConstants.UDS_FETCH_RIGHTS,
                    AccessRulesConstants.USERDATASOURCEPREFIX + userDataSourceName + AccessRulesConstants.UDS_FETCH_RIGHTS);
            accessRulesUdsAccess.put(AccessRulesConstants.USERDATASOURCEPREFIX + userDataSourceId + AccessRulesConstants.UDS_REMOVE_RIGHTS,
                    AccessRulesConstants.USERDATASOURCEPREFIX + userDataSourceName + AccessRulesConstants.UDS_REMOVE_RIGHTS);
        }
        ret.put("USERDATASOURCEACCESSRULES", accessRulesUdsAccess);
        // Insert plugin rules
        for (final AccessRulePlugin accessRulePlugin : ServiceLoader.load(AccessRulePlugin.class)) {
            Map<String,String> accessRulesInCategory = ret.get(accessRulePlugin.getCategory());
            if (accessRulesInCategory==null) {
                accessRulesInCategory = new LinkedHashMap<>();
                ret.put(accessRulePlugin.getCategory(), accessRulesInCategory);
            }
            for (final Entry<String,String> resourceAndName : accessRulePlugin.getRules().entrySet()) {
                accessRulesInCategory.put(resourceAndName.getKey(), resourceAndName.getValue());
            }
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean initializeAuthorizationModule() {
        if (roleDataSession.getAllRoles().isEmpty() && caSession.getAllCaIds().isEmpty()) {
            log.info("No roles or CAs exist, intializing Super Administrator Role with default CLI user.");
            // Create "Super Administrator Role" (with roleId "1" to ensure that upgraded installations still have the same roleId)
            final Role roleToPersist = new Role(null, SUPERADMIN_ROLE, Arrays.asList(StandardRules.ROLE_ROOT.resource()), null);
            roleToPersist.setRoleId(1);
            final Role role = roleDataSession.persistRole(roleToPersist);
            // We won't create any RoleMember for a Super Admin certificate here
            // Add CLI user role member
            final String username = EjbcaConfiguration.getCliDefaultUser();
            roleMemberDataSession.persistRoleMember(new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, CliAuthenticationTokenMetaData.TOKEN_TYPE,
                    RoleMember.NO_ISSUER, CliUserAccessMatchValue.USERNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                    username, role.getRoleId(), null, null));
            // Add CLI user end entity
            final UserData userData = new UserData(username, EjbcaConfiguration.getCliDefaultPassword(), false, "UID=" + username, 0, null, null, null, 0,
                    SecConst.EMPTY_ENDENTITYPROFILE, 0, 0, 0, null);
            userData.setStatus(EndEntityConstants.STATUS_GENERATED);
            if (entityManager.find(UserData.class, username)==null) {
                entityManager.persist(userData);
            }
            return true;
        }
        log.info("Roles or CAs exist, not intializing " + SUPERADMIN_ROLE);
        return false;
    }

    /*
     * Note:
     * This is expected to be invoked by the CLI user during "ant install" or similar operation.
     * The StartupSingletonBean should have initialized by the SUPERADMIN_ROLE at startup on a fresh system and authorized the CLI user.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean initializeAuthorizationModuleWithSuperAdmin(AuthenticationToken authenticationToken, int caId, String superAdminCN) throws AuthorizationDeniedException {
        if (roleDataSession.getAllRoles().isEmpty() && caSession.getAllCaIds().isEmpty()) {
            log.info("The Role '" + SUPERADMIN_ROLE + "' has not been initialized. Cannot add SuperAdmin '" + superAdminCN + "'.");
            return false;
        }
        final Role role = roleSession.getRole(authenticationToken, null, SUPERADMIN_ROLE);
        if (role==null) {
            log.info("The Role '" + SUPERADMIN_ROLE + "' does not exist. Cannot add SuperAdmin '" + superAdminCN + "'.");
            return false;
        }
        // We don't care if the caller has done this before. If the caller is authorized we comply.
        roleMemberSession.persist(authenticationToken, new RoleMember(RoleMember.ROLE_MEMBER_ID_UNASSIGNED, X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE,
                caId, X500PrincipalAccessMatchValue.WITH_COMMONNAME.getNumericValue(), AccessMatchType.TYPE_EQUALCASE.getNumericValue(),
                superAdminCN, role.getRoleId(), null, null));
        return true;
    }

    @Override
    public AccessSet getAccessSetForAuthToken(AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        final HashMap<String, Boolean> accessRules = authorizationSession.getAccessAvailableToAuthenticationToken(authenticationToken);
        final Set<String> allResources = new HashSet<>(getAllResources(false).keySet());
        // Since we no longer support the recursive rule in AccessSets from EJBCA 6.8.0 we also need to include non-configurable access rules
        // ..but this is kind of theoretical since we currently don't support any of these operations from the RA
        allResources.add(StandardRules.CAADD.resource());
        allResources.add(StandardRules.CAREMOVE.resource());
        return new AccessSet(accessRules, allResources);
    }
}
