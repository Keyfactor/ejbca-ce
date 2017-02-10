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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRulePlugin;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.util.ValueExtractor;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * This session bean handles complex authorization queries.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ComplexAccessControlSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ComplexAccessControlSessionBean implements ComplexAccessControlSessionLocal, ComplexAccessControlSessionRemote {

    private static final Logger log = Logger.getLogger(ComplexAccessControlSessionBean.class);

    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EnterpriseEditionEjbBridgeSessionLocal enterpriseEditionEjbBridgeSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private RoleManagementSessionLocal roleMgmtSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean initializeAuthorizationModule() {
        Collection<AdminGroupData> roles = roleAccessSession.getAllRoles();
        List<CAData> cas = CAData.findAll(entityManager);
        if ((roles.size() == 0) && (cas.size() == 0)) {
            log.info("No roles or CAs exist, intializing Super Administrator Role with default CLI user.");
            createSuperAdministrator();
            return true;
        } else {
            log.info("Roles or CAs exist, not intializing " + SUPERADMIN_ROLE);
            return false;
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createSuperAdministrator() {
        //Create the GUI Super Admin
        AdminGroupData role = roleAccessSession.findRole(SUPERADMIN_ROLE);
        Map<Integer, AccessUserAspectData> newUsers = new HashMap<Integer, AccessUserAspectData>();   
        AdminGroupData oldSuperAdminRole = roleAccessSession.findRole(TEMPORARY_SUPERADMIN_ROLE);
        if (role == null) {
            log.debug("Creating new role '" + SUPERADMIN_ROLE + "'.");
            role = new AdminGroupData(1, SUPERADMIN_ROLE);
            entityManager.persist(role);
        } else {
            log.debug("'" + SUPERADMIN_ROLE + "' already exists, not creating new.");            
        }

        Map<Integer, AccessRuleData> rules = role.getAccessRules();
        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
        if (!rules.containsKey(rule.getPrimaryKey())) {
            log.debug("Adding new rule '/' to " + SUPERADMIN_ROLE + ".");
            Map<Integer, AccessRuleData> newrules = new HashMap<Integer, AccessRuleData>();
            newrules.put(rule.getPrimaryKey(), rule);
            role.setAccessRules(newrules);
        } else {
            log.debug("rule '/' already exists in " + SUPERADMIN_ROLE + ".");
        }
        //Pick up the aspects from the old temp. super admin group and add them to the new one.        
        if (oldSuperAdminRole != null) {
            Map<Integer, AccessUserAspectData> oldSuperAdminAspects = oldSuperAdminRole.getAccessUsers();
            Map<Integer, AccessUserAspectData> existingSuperAdminAspects = role.getAccessUsers();
            for (AccessUserAspectData aspect : oldSuperAdminAspects.values()) {
                AccessMatchValue matchWith = AccessMatchValueReverseLookupRegistry.INSTANCE.performReverseLookup(
                        X509CertificateAuthenticationTokenMetaData.TOKEN_TYPE, aspect.getMatchWith());
                AccessUserAspectData superAdminUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, aspect.getCaId(), matchWith,
                        aspect.getMatchTypeAsType(), aspect.getMatchValue());
                if (existingSuperAdminAspects.containsKey(superAdminUserAspect.getPrimaryKey())) {
                    log.debug(SUPERADMIN_ROLE + " already contains aspect matching " + aspect.getMatchValue() + " for CA with ID " + aspect.getCaId());
                } else {
                    newUsers.put(superAdminUserAspect.getPrimaryKey(), superAdminUserAspect);
                }
            }
        }
           
        //Create the CLI Default User
        Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
        AccessUserAspectData defaultCliUserAspect = new AccessUserAspectData(SUPERADMIN_ROLE, 0, CliUserAccessMatchValue.USERNAME,
                AccessMatchType.TYPE_EQUALCASE, EjbcaConfiguration.getCliDefaultUser());
        if (!users.containsKey(defaultCliUserAspect.getPrimaryKey())) {
            log.debug("Adding new AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' to " + SUPERADMIN_ROLE + ".");
              
            newUsers.put(defaultCliUserAspect.getPrimaryKey(), defaultCliUserAspect);
            UserData defaultCliUserData = new UserData(EjbcaConfiguration.getCliDefaultUser(), EjbcaConfiguration.getCliDefaultPassword(), false, "UID="
                    + EjbcaConfiguration.getCliDefaultUser(), 0, null, null, null, 0, SecConst.EMPTY_ENDENTITYPROFILE, 0, 0, 0, null);
            defaultCliUserData.setStatus(EndEntityConstants.STATUS_GENERATED);
            if (entityManager.find(UserData.class, defaultCliUserData.getUsername())==null) {
                entityManager.persist(defaultCliUserData);
            }
        } else {
            log.debug("AccessUserAspect '"+EjbcaConfiguration.getCliDefaultUser()+"' already exists in " + SUPERADMIN_ROLE + ".");            
        }
        //Add all created aspects to role
        role.setAccessUsers(newUsers);
        
    }

    public void initializeAuthorizationModule(AuthenticationToken admin, int caid, String superAdminCN) throws RoleExistsException,
            AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">initializeAuthorizationModule(" + caid + ", " + superAdminCN);
        }
        // In this method we need to use the entityManager explicitly instead of the role management session bean.
        // This is because it is also used to initialize the first rule that will allow the AlwayAllowAuthenticationToken to do anything.
        // Without this role and access rule we are not authorized to use the role management session bean
        AdminGroupData role = roleAccessSession.findRole(SUPERADMIN_ROLE);
        if (role == null) {
            log.debug("Creating new role '" + SUPERADMIN_ROLE + "'.");
            roleMgmtSession.create(admin, SUPERADMIN_ROLE);
        }
        Map<Integer, AccessRuleData> rules = role.getAccessRules();
        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
        try {
        if (!rules.containsKey(rule.getPrimaryKey())) {
            log.debug("Adding new rule '/' to " + SUPERADMIN_ROLE + ".");
            Collection<AccessRuleData> newrules = new ArrayList<AccessRuleData>();
            newrules.add(rule);
            roleMgmtSession.addAccessRulesToRole(admin, role, newrules);
        }
        Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
        AccessUserAspectData aua = new AccessUserAspectData(SUPERADMIN_ROLE, caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE,
                superAdminCN);
        if (!users.containsKey(aua.getPrimaryKey())) {
            log.debug("Adding new AccessUserAspect for '" + superAdminCN + "' to " + SUPERADMIN_ROLE + ".");
            Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
            subjects.add(aua);
            roleMgmtSession.addSubjectsToRole(admin, role, subjects);
        }
        } catch(RoleNotFoundException e) {
            throw new IllegalStateException("Newly created role " + role.getRoleName() + " was not found.", e);
        }
        accessTreeUpdateSession.signalForAccessTreeUpdate();
        accessControlSession.forceCacheExpire();
        if (log.isTraceEnabled()) {
            log.trace("<initializeAuthorizationModule(" + caid + ", " + superAdminCN);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String, Set<String>> getAuthorizedAvailableAccessRules(AuthenticationToken authenticationToken, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds,
            Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules) {
        return getAvailableAccessRules(authenticationToken, enableendentityprofilelimitations, usehardtokenissuing, usekeyrecovery,
                authorizedEndEntityProfileIds, authorizedUserDataSourceIds, customaccessrules, false);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String, Set<String>> getAllAccessRulesRedactUnauthorizedCas(AuthenticationToken authenticationToken, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds,
            Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules) {
        return getAvailableAccessRules(authenticationToken, enableendentityprofilelimitations, usehardtokenissuing, usekeyrecovery,
                authorizedEndEntityProfileIds, authorizedUserDataSourceIds, customaccessrules, true);
    }
    /**
     * Will collect either all authorized access rules, or all access rules barring those relating to CAs (or CPs or EEPs dependent on CAs), EEPs or CPs which
     * the current admin is authorized to, depending on the 
     * 
    * @param admin is the administrator calling the method.
    * @param availableCaIds A Collection<Integer> of all CA IDs
    * @param enableendentityprofilelimitations Include End Entity Profile access rules
    * @param usehardtokenissuing Include Hard Token access rules
    * @param usekeyrecovery Include Key Recovery access rules
    * @param authorizedEndEntityProfileIds A Collection<Integer> of all authorized End Entity Profile IDs
    * @param authorizedUserDataSourceIds A Collection<Integer> of all authorized user data sources IDs
    * @param restrictToCaChecks set to true to return all access rules, barring those relating to CA's, EEPs or CPs which the admin doesn't have access to. 
    * @param 
    * @return a LinkedHashMap of strings representing the available access rules, keyed by category
    */
    private Map<String, Set<String>> getAvailableAccessRules(AuthenticationToken authenticationToken, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds,
            Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules, boolean restrictToCaChecks) {
        if (log.isTraceEnabled()) {
            log.trace(">getAuthorizedAvailableAccessRules");
        }
        Map<String, Set<String>> accessrules = new LinkedHashMap<String, Set<String>>();
        
        //Role based access rules 
        Set<String> roleRules = new LinkedHashSet<String>();      
        roleRules.add(AccessRulesConstants.ROLEACCESSRULES[0]);
        roleRules.add(AccessRulesConstants.ROLEACCESSRULES[1]);
        if (accessControlSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource()) || restrictToCaChecks) {
            roleRules.add(StandardRules.ROLE_ROOT.resource());
        }
        accessrules.put("ROLEBASEDACCESSRULES", roleRules);
        
        //Standard rules
        Set<String> standardRules = new LinkedHashSet<String>();          
        // Insert Standard Access Rules.
        for (int i = 0; i < AccessRulesConstants.STANDARDREGULARACCESSRULES.length; i++) {
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.STANDARDREGULARACCESSRULES[i]) || restrictToCaChecks) {
                standardRules.add(AccessRulesConstants.STANDARDREGULARACCESSRULES[i]);
            }
        }
        if (usehardtokenissuing) {
            for (int i = 0; i < AccessRulesConstants.HARDTOKENACCESSRULES.length; i++) {
                standardRules.add(AccessRulesConstants.HARDTOKENACCESSRULES[i]);
            }
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_VIEWHARDTOKENS) || restrictToCaChecks) {
                standardRules.add(AccessRulesConstants.REGULAR_VIEWHARDTOKENS);
            }
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_VIEWPUKS) || restrictToCaChecks) {
                standardRules.add(AccessRulesConstants.REGULAR_VIEWPUKS);
            }
        }
        if (usekeyrecovery) {
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY) || restrictToCaChecks) {
                standardRules.add(AccessRulesConstants.REGULAR_KEYRECOVERY);
            }
        }
        // Insert custom access rules
        for (int i = 0; i < customaccessrules.length; i++) {
            if (!customaccessrules[i].trim().equals("")) {
                if (accessControlSession.isAuthorizedNoLogging(authenticationToken, customaccessrules[i].trim()) || restrictToCaChecks) {
                    standardRules.add(customaccessrules[i].trim());
                }

            }
        }
        accessrules.put("REGULARACCESSRULES", standardRules);
        
        // Insert available CA access rules
        Set<String> caAccessRules = new LinkedHashSet<String>();     
        if (accessControlSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAACCESSBASE.resource()) || restrictToCaChecks) {
            caAccessRules.add(StandardRules.CAACCESSBASE.resource());
        }
        for (int caId : caSession.getAuthorizedCaIds(authenticationToken)) {
            caAccessRules.add(StandardRules.CAACCESS.resource() + caId);
        }
        accessrules.put("CAACCESSRULES", caAccessRules);
        
        //End entity profile rules
        Set<String> endEntityProfileRules = new LinkedHashSet<String>();     
        if (enableendentityprofilelimitations) {
            // Add most basic rule if authorized to it.
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEBASE) || restrictToCaChecks) {
                endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
            } else {
                // Add it to SuperAdministrator anyway
                if (accessControlSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
                    endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
                }
            }
            // Add all authorized End Entity Profiles
            for (int profileid : authorizedEndEntityProfileIds) {
                // Administrator is authorized to this End Entity Profile, add it.
                if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid)) {
                    endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid);
                    for (int j = 0; j < AccessRulesConstants.ENDENTITYPROFILE_ENDINGS.length; j++) {
                        endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.ENDENTITYPROFILE_ENDINGS[j]);
                    }
                    if (usehardtokenissuing) {
                        endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_RIGHTS);
                        endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
                    }
                    if (usekeyrecovery) {
                        endEntityProfileRules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.KEYRECOVERY_RIGHTS);
                    }
                }
            }
        }
        accessrules.put("ENDENTITYPROFILEACCESSR", endEntityProfileRules);
        
        //Crypto token rules
        Set<String> cryptoTokenRules = new HashSet<String>();     
        for (CryptoTokenRules rule : CryptoTokenRules.values()) {
            final String fullRule = rule.resource();
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, fullRule)) {
                cryptoTokenRules.add(fullRule);
            }
        }
        final List<Integer> allCryptoTokenIds = cryptoTokenSession.getCryptoTokenIds();
        for (Integer cryptoTokenId : allCryptoTokenIds) {
            for (CryptoTokenRules rule : CryptoTokenRules.values()) {
                if (!rule.equals(CryptoTokenRules.BASE) && !rule.equals(CryptoTokenRules.MODIFY_CRYPTOTOKEN) && !rule.equals(CryptoTokenRules.DELETE_CRYPTOTOKEN)) {
                    final String fullRule = rule.resource() + "/" + cryptoTokenId;
                    if (accessControlSession.isAuthorizedNoLogging(authenticationToken, fullRule)) {
                        cryptoTokenRules.add(fullRule);
                    }
                }
            }
        }
        accessrules.put("CRYPTOTOKENACCESSRULES", cryptoTokenRules);
       
        // Insert User data source access rules
        Set<String> userDataSourceRules = new HashSet<String>();
        if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.USERDATASOURCEBASE) || restrictToCaChecks) {
            userDataSourceRules.add(AccessRulesConstants.USERDATASOURCEBASE);
        }
        for (int id : authorizedUserDataSourceIds) {
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id
                    + AccessRulesConstants.UDS_FETCH_RIGHTS) || restrictToCaChecks) {
                userDataSourceRules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS);
            }
            if (accessControlSession.isAuthorizedNoLogging(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id
                    + AccessRulesConstants.UDS_REMOVE_RIGHTS) || restrictToCaChecks) {
                userDataSourceRules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS);
            }
        }
        accessrules.put("USERDATASOURCEACCESSRULES", userDataSourceRules);
             
        //Insert plugin rules 
        ServiceLoader<? extends AccessRulePlugin> serviceLoader = ServiceLoader.load(AccessRulePlugin.class);
        for (AccessRulePlugin accessRulePlugin : serviceLoader) {
            Set<String> pluginRules = new LinkedHashSet<String>();
            for (String rule : accessRulePlugin.getRules()) {
                if (accessControlSession.isAuthorizedNoLogging(authenticationToken, rule) || restrictToCaChecks) {
                    pluginRules.add(rule);
                }
            }
            accessrules.put(accessRulePlugin.getCategory(), pluginRules);
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<getAuthorizedAvailableAccessRules");
        }
        return accessrules;
    }

    @Override
    public Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin, String rapriviledge,
            Collection<Integer> availableEndEntityProfileId) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        Iterator<Integer> iter = availableEndEntityProfileId.iterator();
        while (iter.hasNext()) {
            Integer profileid = iter.next();
            if (accessControlSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rapriviledge)) {
                returnval.add(profileid);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Admin not authorized to end entity profile: " + profileid);
                }
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsEndEntityProfileInRules(int profileid) {
        if (log.isTraceEnabled()) {
            log.trace(">existsEndEntityProfileInRules(" + profileid + ")");
        }
        final String whereClause = "accessRule = '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "' OR accessRule LIKE '"
                + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "/%'";
        Query query = entityManager.createNativeQuery("SELECT COUNT(*) FROM AccessRulesData a WHERE " + whereClause);
        long count = ValueExtractor.extractLongValue(query.getSingleResult());
        if (log.isTraceEnabled()) {
            log.trace("<existsEndEntityProfileInRules(" + profileid + "): " + count);
        }
        return count > 0;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void forceRemoteCacheExpire() {
        log.trace(">forceRemoteCacheExpire");
        enterpriseEditionEjbBridgeSession.requestClearEnterpriseAuthorizationCaches();
        log.trace("<forceRemoteCacheExpire");
    }
    
}
