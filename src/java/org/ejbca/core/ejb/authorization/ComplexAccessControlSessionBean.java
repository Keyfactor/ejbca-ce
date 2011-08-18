/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessTree;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessMatchValue;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
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
    private CaSessionLocal caSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private RoleManagementSessionLocal roleMgmtSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    private static final String SUPERADMIN_ROLE = "Super Administrator Role";
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void initializeAuthorizationModule() {
    	Collection<RoleData> roles = roleAccessSession.getAllRoles();
    	List<CAData> cas = CAData.findAll(entityManager);
    	if ((roles.size() == 0) && (cas.size() == 0)) {
    		log.info("No roles or CAs exist, intializing Super Administrator Role with caid 0 and superadminCN empty.");
    		log.debug("Creating new role '"+SUPERADMIN_ROLE+"'.");
    		RoleData role = new RoleData(1, SUPERADMIN_ROLE);
    		entityManager.persist(role);
    		log.debug("Adding new rule '/' to "+SUPERADMIN_ROLE+".");
        	AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, "/", AccessRuleState.RULE_ACCEPT, true);
        	Map<Integer, AccessRuleData> newrules = new HashMap<Integer, AccessRuleData>();
        	newrules.put(rule.getPrimaryKey(), rule);
        	role.setAccessRules(newrules);
    		log.debug("Adding new AccessUserAspect 'NONE' to "+SUPERADMIN_ROLE+".");
        	Map<Integer, AccessUserAspectData> newUsers = new HashMap<Integer, AccessUserAspectData>();
        	AccessUserAspectData aua = new AccessUserAspectData(SUPERADMIN_ROLE, 0, AccessMatchValue.NONE, AccessMatchType.TYPE_EQUALCASE, "");
        	newUsers.put(aua.getPrimaryKey(), aua);
        	role.setAccessUsers(newUsers);    		
    	} else {
    		log.error("Roles or CAs exist, not intializing "+SUPERADMIN_ROLE);			
    	}
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void initializeAuthorizationModule(AuthenticationToken admin, int caid, String superAdminCN) throws RoleExistsException, AuthorizationDeniedException, AccessRuleNotFoundException, RoleNotFoundException {
    	if (log.isTraceEnabled()) {
    		log.trace(">initializeAuthorizationModule("+caid+", "+superAdminCN);
    	}
    	// In this method we need to use the entityManager explicitly instead of the role management session bean.
    	// This is because it is also used to initialize the first rule that will allow the AlwayAllowAuthenticationToken to do anything.
    	// Without this role and access rule we are not authorized to use the role management session bean 
    	RoleData role = roleAccessSession.findRole(SUPERADMIN_ROLE);
    	if (role == null) {
    		log.debug("Creating new role '"+SUPERADMIN_ROLE+"'.");
    		roleMgmtSession.create(admin, SUPERADMIN_ROLE);
    	}
    	Map<Integer, AccessRuleData> rules = role.getAccessRules();
    	AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, "/", AccessRuleState.RULE_ACCEPT, true);
    	if (!rules.containsKey(rule.getPrimaryKey())) {
    		log.debug("Adding new rule '/' to "+SUPERADMIN_ROLE+".");
        	Collection<AccessRuleData> newrules = new ArrayList<AccessRuleData>();
        	newrules.add(rule);
    		roleMgmtSession.addAccessRulesToRole(admin, role, newrules);
    	}
    	Map<Integer, AccessUserAspectData> users = role.getAccessUsers();
    	AccessUserAspectData aua = new AccessUserAspectData(SUPERADMIN_ROLE, caid, AccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, superAdminCN);
    	if (!users.containsKey(aua.getPrimaryKey())) {
    		log.debug("Adding new AccessUserAspect for '"+superAdminCN+"' to "+SUPERADMIN_ROLE+".");
        	Collection<AccessUserAspectData> subjects = new ArrayList<AccessUserAspectData>();
        	subjects.add(aua);
        	roleMgmtSession.addSubjectsToRole(admin, role, subjects);
    	}
    	accessTreeUpdateSession.signalForAccessTreeUpdate();
    	accessControlSession.forceCacheExpire();
    	if (log.isTraceEnabled()) {
    		log.trace("<initializeAuthorizationModule("+caid+", "+superAdminCN);
    	}
	}
	
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    /*
     * FIXME: Test this method! 
     */
    public Collection<RoleData> getAllRolesAuthorizedToEdit(AuthenticationToken authenticationToken) {
        List<RoleData> result = new ArrayList<RoleData>();
        for (RoleData role : roleAccessSession.getAllRoles()) {
            if (isAuthorizedToEditRole(authenticationToken, role)) {
                result.add(role);
            }
        }
        return result;
    }

    /**
     * Method used to return an ArrayList of Integers indicating which CAids an administrator is authorized to access.
     * 
     * @return Collection of Integer
     */
    public Collection<Integer> getAuthorizedCAIds(AuthenticationToken admin) {
        List<Integer> returnval = new ArrayList<Integer>();
        for (Integer caid : caSession.getAvailableCAs()) {
            if (accessControlSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid.toString())) {
                returnval.add(caid);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Admin not authorized to CA: " + caid);
                }
            }
        }
        return returnval;
    }

    @Override
    /*
     * FIXME: Test this method! 
     */
    public boolean isAuthorizedToEditRole(AuthenticationToken authenticationToken, RoleData role) {
        // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
        for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
            if (!accessControlSession.isAuthorizedNoLog(authenticationToken, StandardRules.CAACCESS.resource() + accessUserAspect.getCaId())) {
                return false;
            }
        }
        // Secondly, examine all resources in this role and establish access rights
        for (AccessRuleData accessRule : role.getAccessRules().values()) {
            String rule = accessRule.getAccessRuleName();
            // Check only CA rules
            if (rule.startsWith(StandardRules.CAACCESS.resource())) {
                if (!accessControlSession.isAuthorizedNoLog(authenticationToken, rule)) {
                    return false;
                }
            }
        }
        // Everything's A-OK, role is good.
        return true;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<String> getAuthorizedAvailableAccessRules(AuthenticationToken authenticationToken, 
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery,
            Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds, String[] customaccessrules) {
        ArrayList<String> accessrules = new ArrayList<String>();

        accessrules.add(AccessRulesConstants.ROLEACCESSRULES[0]);
        accessrules.add(AccessRulesConstants.ROLEACCESSRULES[1]);
        if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            accessrules.add(AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        }

        // Insert Standard Access Rules.
        for (int i = 0; i < AccessRulesConstants.STANDARDREGULARACCESSRULES.length; i++) {
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.STANDARDREGULARACCESSRULES[i])) {
                accessrules.add(AccessRulesConstants.STANDARDREGULARACCESSRULES[i]);
            }
        }
        for (int i = 0; i < AccessRulesConstants.VIEWLOGACCESSRULES.length; i++) {
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.VIEWLOGACCESSRULES[i])) {
                accessrules.add(AccessRulesConstants.VIEWLOGACCESSRULES[i]);
            }
        }

        if (usehardtokenissuing) {
            for (int i = 0; i < AccessRulesConstants.HARDTOKENACCESSRULES.length; i++) {
                accessrules.add(AccessRulesConstants.HARDTOKENACCESSRULES[i]);
            }
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
                accessrules.add(AccessRulesConstants.REGULAR_VIEWHARDTOKENS);
            }
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_VIEWPUKS)) {
                accessrules.add(AccessRulesConstants.REGULAR_VIEWPUKS);
            }
        }

        if (usekeyrecovery) {
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY)) {
                accessrules.add(AccessRulesConstants.REGULAR_KEYRECOVERY);
            }
        }

        if (enableendentityprofilelimitations) {
            // Add most basic rule if authorized to it.
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEBASE)) {
                accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
            } else {
                // Add it to SuperAdministrator anyway
                if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                    accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
                }
            }
            // Add all authorized End Entity Profiles
            for (int profileid : authorizedEndEntityProfileIds) {
                // Administrator is authorized to this End Entity Profile, add it.
                if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid)) {
                    accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid);
                    for (int j = 0; j < AccessRulesConstants.ENDENTITYPROFILE_ENDINGS.length; j++) {
                        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.ENDENTITYPROFILE_ENDINGS[j]);
                    }
                    if (usehardtokenissuing) {
                        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_RIGHTS);
                        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
                    }
                    if (usekeyrecovery) {
                        accessrules.add(AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + AccessRulesConstants.KEYRECOVERY_RIGHTS);
                    }
                }
            }
        }
        // Insert User data source access rules
        if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEBASE)) {
            accessrules.add(AccessRulesConstants.USERDATASOURCEBASE);
        }
        for (int id : authorizedUserDataSourceIds) {
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id
                    + AccessRulesConstants.UDS_FETCH_RIGHTS)) {
                accessrules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS);
            }
            if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id
                    + AccessRulesConstants.UDS_REMOVE_RIGHTS)) {
                accessrules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS);
            }
        }
        // Insert available CA access rules
        if (accessControlSession.isAuthorizedNoLog(authenticationToken, AccessRulesConstants.CABASE)) {
            accessrules.add(AccessRulesConstants.CABASE);
        }
        for (int caId : getAuthorizedCAIds(authenticationToken)) {
            accessrules.add(AccessRulesConstants.CAPREFIX + caId);
        }

        // Insert custom access rules
        for (int i = 0; i < customaccessrules.length; i++) {
            if (!customaccessrules[i].trim().equals("")) {
                if(accessControlSession.isAuthorizedNoLog(authenticationToken, customaccessrules[i].trim())) {
                    accessrules.add(customaccessrules[i].trim());
                }
              
            }
        }
        return accessrules;
    }
    
    @Override
    public Collection<Integer> getAuthorizedEndEntityProfileIds(AuthenticationToken admin, String rapriviledge, Collection<Integer> availableEndEntityProfileId){
        ArrayList<Integer> returnval = new ArrayList<Integer>();  
        Iterator<Integer> iter = availableEndEntityProfileId.iterator();
        while(iter.hasNext()){
            Integer profileid = iter.next();
            if(accessControlSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rapriviledge)) {     
                returnval.add(profileid); 
            } else {
                if (log.isDebugEnabled()) {
                        log.debug("Admin not authorized to end entity profile: "+profileid);
                }               
            }
        }
        return returnval;
    }

    @Override
    public Collection<RoleData> getAuthorizedAdminGroups(AuthenticationToken admin, String resource) {
    	ArrayList<RoleData> authissueingadmgrps = new ArrayList<RoleData>();
    	// Look for Roles that have access rules that allows the group access to the rule below.
    	Collection<RoleData> roles = getAllRolesAuthorizedToEdit(admin);
    	Collection<RoleData> onerole = new ArrayList<RoleData>();
    	for (RoleData role : roles) {
    		// We want to check all roles if they are authorized, we can do that with a "private" AccessTree.
    		// Probably quite inefficient but...
    		AccessTree tree = new AccessTree();
    		onerole.clear();
    		onerole.add(role);
    		tree.buildTree(onerole);
    		// Create an AlwaysAllowAuthenticationToken just to find out if there is 
    		// an access rule for the requested resource
    		AlwaysAllowLocalAuthenticationToken token = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("isGroupAuthorized"));
    		if (tree.isAuthorized(token, resource)) {
    			authissueingadmgrps.add(role);
    		}
    	}
    	return authissueingadmgrps;
    }


}
