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

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationTokenMetaData;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.EnterpriseEditionEjbBridgeSessionLocal;
import org.ejbca.core.ejb.authentication.cli.CliUserAccessMatchValue;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.SecConst;

/**
 * This session bean handles complex authorization queries.
 * 
 * @version $Id$
 * 
 */
@Deprecated // Use new AuthorizationSystemSessionBean introduced in EJBCA 6.8.0 instead 
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
    @Deprecated
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
}
