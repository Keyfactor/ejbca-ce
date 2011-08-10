/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.control;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.cache.AccessTreeCache;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.DefaultRoles;
import org.ejbca.core.model.log.Admin;

/**
 * Based on cesecore version: AccessControlSessionBean.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessControlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessControlSessionBean implements AccessControlSessionLocal, AccessControlSessionRemote {

    private static final Logger log = Logger.getLogger(AccessControlSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;

    /** Cache for authorization data */
    private static AccessTreeCache accessTreeCache;

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

    @Override
    /*
     * FIXME: Test this method! 
     */
    public boolean isAuthorizedToEditRole(AuthenticationToken authenticationToken, RoleData role) {
        // Firstly, make sure that authentication token authorized for all access user aspects in role, by checking against the CA that produced them.
        for (AccessUserAspectData accessUserAspect : role.getAccessUsers().values()) {
            if (!isAuthorizedNoLog(authenticationToken, StandardRules.CAACCESS.resource() + accessUserAspect.getCaId())) {
                return false;
            }
        }
        // Secondly, examine all resources in this role and establish access rights
        for (AccessRuleData accessRule : role.getAccessRules().values()) {
            String rule = accessRule.getAccessRuleName();
            // Check only CA rules
            if (rule.startsWith(StandardRules.CAACCESS.resource())) {
                if (!isAuthorizedNoLog(authenticationToken, rule)) {
                    return false;
                }
            }
        }
        // Everything's A-OK, role is good.
        return true;
    }

    @Override
    public boolean isAuthorized(AuthenticationToken authenticationToken, String resource) {
        if (isAuthorizedNoLog(authenticationToken, resource)) {
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("resource", resource);
            securityEventsLoggerSession.log(EventTypes.ACCESS_CONTROL, EventStatus.SUCCESS, ModuleTypes.ACCESSCONTROL, ServiceTypes.CORE,
                    authenticationToken.toString(), null, null, null, details);
            return true;
        } else {
            return false;
        }
    }

    @Override
    public boolean isAuthorizedNoLog(AuthenticationToken authenticationToken, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree(authenticationToken);
        }
        return accessTreeCache.getAccessTree().isAuthorized(authenticationToken, resource);
    }

    @Override
    public void forceCacheExpire() {
        if (log.isTraceEnabled()) {
            log.trace("forceCacheExpire");
        }
        if (accessTreeCache != null) {
            accessTreeCache.forceCacheExpire();
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    // @Override
    public Collection<String> getAuthorizedAvailableAccessRules(AuthenticationToken authenticationToken, Collection<Integer> availableCaIds,
            boolean enableendentityprofilelimitations, boolean usehardtokenissuing, boolean usekeyrecovery,
            Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds) {
        ArrayList<String> accessrules = new ArrayList<String>();

        accessrules.add(AccessRulesConstants.ROLEACCESSRULES[0]);
        accessrules.add(AccessRulesConstants.ROLEACCESSRULES[1]);
        if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
            accessrules.add(AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        }

        // Insert Standard Access Rules.
        for (int i = 0; i < AccessRulesConstants.STANDARDREGULARACCESSRULES.length; i++) {
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.STANDARDREGULARACCESSRULES[i])) {
                accessrules.add(AccessRulesConstants.STANDARDREGULARACCESSRULES[i]);
            }
        }
        for (int i = 0; i < AccessRulesConstants.VIEWLOGACCESSRULES.length; i++) {
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.VIEWLOGACCESSRULES[i])) {
                accessrules.add(AccessRulesConstants.VIEWLOGACCESSRULES[i]);
            }
        }

        if (usehardtokenissuing) {
            for (int i = 0; i < AccessRulesConstants.HARDTOKENACCESSRULES.length; i++) {
                accessrules.add(AccessRulesConstants.HARDTOKENACCESSRULES[i]);
            }
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
                accessrules.add(AccessRulesConstants.REGULAR_VIEWHARDTOKENS);
            }
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_VIEWPUKS)) {
                accessrules.add(AccessRulesConstants.REGULAR_VIEWPUKS);
            }
        }

        if (usekeyrecovery) {
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.REGULAR_KEYRECOVERY)) {
                accessrules.add(AccessRulesConstants.REGULAR_KEYRECOVERY);
            }
        }

        if (enableendentityprofilelimitations) {
            // Add most basic rule if authorized to it.
            if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEBASE)) {
                accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
            } else {
                // Add it to SuperAdministrator anyway
                if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ROLE_SUPERADMINISTRATOR)) {
                    accessrules.add(AccessRulesConstants.ENDENTITYPROFILEBASE);
                }
            }
            // Add all authorized End Entity Profiles
            for (int profileid : authorizedEndEntityProfileIds) {
                // Administrator is authorized to this End Entity Profile, add it.
                if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid)) {
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
        if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEBASE)) {
            accessrules.add(AccessRulesConstants.USERDATASOURCEBASE);
        }
        for (int id : authorizedUserDataSourceIds) {
            if(isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS)) {
                accessrules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_FETCH_RIGHTS);
            }
            if(isAuthorizedNoLog(authenticationToken, AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS)) {
                accessrules.add(AccessRulesConstants.USERDATASOURCEPREFIX + id + AccessRulesConstants.UDS_REMOVE_RIGHTS);
            }
        }
        //Insert available CA access rules
        if (isAuthorizedNoLog(authenticationToken, AccessRulesConstants.CABASE)) {
            accessrules.add(AccessRulesConstants.CABASE);
        }
        HashSet<Integer> authorizedcaids = new HashSet<Integer>();
        authorizedcaids.addAll(authorizer.getAuthorizedCAIds(admin, availableCaIds));
        
        for(int caId : authorizedcaids) {
                accessrules.add(AccessRulesConstants.CAPREFIX + caId);  
        }
        //Insert custom access rules
        insertCustomAccessRules(admin, accessrules);
        return accessrules;
    }

    /**
     * Method used check if a reconstruction of authorization tree is needed in the authorization beans.
     * 
     * @return true if update is needed.
     */
    private boolean updateNeccessary() {
        boolean ret = false;
        // Only do the actual SQL query if we might update the configuration due to cache time anyhow
        if (accessTreeCache == null) {
            ret = true;
        } else if (accessTreeCache.needsUpdate()) {
            ret = accessTreeUpdateSession.getAccessTreeUpdateData().updateNeccessary(accessTreeCache.getAccessTreeUpdateNumber());
            // we don't want to run the above query often
        }
        if (log.isTraceEnabled()) {
            log.trace("updateNeccessary: " + false);
        }
        return ret;
    }

    /**
     * method updating authorization tree.
     */
    private void updateAuthorizationTree(AuthenticationToken authenticationToken) {
        if (log.isTraceEnabled()) {
            log.trace(">updateAuthorizationTree");
        }
        int authorizationtreeupdatenumber = accessTreeUpdateSession.getAccessTreeUpdateData().getAccessTreeUpdateNumber();
        if (accessTreeCache == null) {
            accessTreeCache = new AccessTreeCache();
        }

        accessTreeCache.updateAccessTree(roleAccessSession.getAllRoles(), authorizationtreeupdatenumber);
        if (log.isTraceEnabled()) {
            log.trace("<updateAuthorizationTree");
        }

    }

}
