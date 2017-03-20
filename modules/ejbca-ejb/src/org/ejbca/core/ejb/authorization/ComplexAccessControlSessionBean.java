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

import java.util.HashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.SecConst;

/**
 * This session bean handles complex authorization queries.
 * 
 * @deprecated since EJBCA 6.8.0 and only kept for upgrade reasons (from EJBCA 4 to 5)
 * @version $Id$
 */
@Deprecated 
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ComplexAccessControlSessionBean implements ComplexAccessControlSessionLocal {

    private static final Logger log = Logger.getLogger(ComplexAccessControlSessionBean.class);

    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    private AdminGroupData findRole(final String roleName) {
        final TypedQuery<AdminGroupData> query = entityManager.createQuery("SELECT a FROM AdminGroupData a WHERE a.roleName=:roleName", AdminGroupData.class);
        query.setParameter("roleName", roleName);
        return QueryResultWrapper.getSingleResult(query);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void createSuperAdministrator() {
        // Create the Super Admin
        AdminGroupData role = findRole(SUPERADMIN_ROLE);
        if (role == null) {
            log.debug("Creating new role '" + SUPERADMIN_ROLE + "'.");
            role = new AdminGroupData(1, SUPERADMIN_ROLE);
            entityManager.persist(role);
        } else {
            log.debug("'" + SUPERADMIN_ROLE + "' already exists, not creating new.");            
        }
        AccessRuleData rule = new AccessRuleData(SUPERADMIN_ROLE, StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true);
        if (!role.getAccessRules().containsKey(rule.getPrimaryKey())) {
            log.debug("Adding new rule '/' to " + SUPERADMIN_ROLE + ".");
            Map<Integer, AccessRuleData> newrules = new HashMap<Integer, AccessRuleData>();
            newrules.put(rule.getPrimaryKey(), rule);
            role.setAccessRules(newrules);
        } else {
            log.debug("rule '/' already exists in " + SUPERADMIN_ROLE + ".");
        }
        // Pick up the aspects from the old temp. super admin group and add them to the new one.        
        Map<Integer, AccessUserAspectData> newUsers = new HashMap<Integer, AccessUserAspectData>();
        AdminGroupData oldSuperAdminRole = findRole(TEMPORARY_SUPERADMIN_ROLE);
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
        // Create the CLI Default User
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
        // Add all created aspects to role
        role.setAccessUsers(newUsers);
        accessTreeUpdateSession.signalForAccessTreeUpdate();
    }
}
