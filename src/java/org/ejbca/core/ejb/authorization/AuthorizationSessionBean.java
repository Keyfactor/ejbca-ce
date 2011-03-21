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
import java.util.HashSet;
import java.util.Iterator;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.authorization.AuthorizationTreeUpdateDataSessionLocal;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupDoesNotExistException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * @see AuthorizationSession
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthorizationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthorizationSessionBean implements AuthorizationSessionLocal, AuthorizationSessionRemote {

    private static final Logger log = Logger.getLogger(AuthorizationSessionBean.class);
    private static final long serialVersionUID = 1L;

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationTreeUpdateDataSessionLocal authorizationTreeUpdateDataSession;
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    /** Cache for authorization data */
    private static final AuthorizationCache authCache = new AuthorizationCache();
    
    private static final String[] customaccessrules = EjbcaConfiguration.getCustomAvailableAccessRules();
    
    private Authorizer getAuthorizer() {
        if (authCache.getAuthorizer() == null) {
        	final GlobalConfiguration config = globalConfigurationSession.getCachedGlobalConfiguration(new Admin(Admin.TYPE_INTERNALUSER));
            authCache.setAuthorizer(new Authorizer(getAdminGroups(), config.getEnableCommandLineInterface(), logSession, LogConstants.MODULE_AUTHORIZATION));
        }
        return authCache.getAuthorizer();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isAuthorized(Admin admin, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isAuthorized(admin, resource);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isAuthorizedNoLog(Admin admin, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isAuthorizedNoLog(admin, resource);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorized(admin, adminGroupId, resource);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorizedNoLog(adminGroupId, resource);
    }

    @Override
    public boolean isAuthorizedToGroup(Admin administrator, String admingroupname) throws AdminGroupDoesNotExistException {
        HashSet<Integer> al = new HashSet<Integer>();
        AdminGroupData adminGroupData = AdminGroupData.findByGroupName(entityManager, admingroupname);
        boolean result = true;
        if (adminGroupData != null) {
            Collection<AdminEntity> adminEntityObjects = adminGroupData.getAdminEntityObjects();
            if(adminEntityObjects.isEmpty()) {
                result = true;
            } else {
                for (AdminEntity adminEntity : adminEntityObjects) {
                    int currentCaId = adminEntity.getCaId();
                    if (!al.contains(currentCaId)) {
                        if (!isAuthorizedNoLog(administrator, AccessRulesConstants.CAPREFIX + currentCaId)) {
                            if(log.isDebugEnabled()) {
                                log.debug("Authorization failed for CA ID " + currentCaId + " and " + administrator.getAdminData());
                            }
                            result = false;
                            break;
                        }
                        al.add(currentCaId);
                    }
                }
            }
 
        } else {
            log.error("Could not find admin group " + admingroupname);
            throw new AdminGroupDoesNotExistException("Could not find admin group " + admingroupname);
        }

        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<String> getAuthorizedAvailableAccessRules(Admin admin, Collection<Integer> availableCaIds, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds) {
        AvailableAccessRules availableAccessRules = new AvailableAccessRules(admin, getAuthorizer(), customaccessrules, availableCaIds,
                enableendentityprofilelimitations, usehardtokenissuing, usekeyrecovery);
        return availableAccessRules.getAvailableAccessRules(admin, authorizedEndEntityProfileIds, authorizedUserDataSourceIds);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAuthorizedCAIds(Admin admin, Collection<Integer> availableCaIds) {
        return getAuthorizer().getAuthorizedCAIds(admin, availableCaIds);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection<Integer> availableEndEntityProfileId) {
        return getAuthorizer().getAuthorizedEndEntityProfileIds(admin, rapriviledge, availableEndEntityProfileId);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid) {
    	if (log.isTraceEnabled()) {
        	log.trace(">existsEndEntityProfileInRules("+profileid+")");    		
    	}
    	final String whereClause = "accessRule = '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "' OR accessRule LIKE '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "/%'";
        long count = AccessRulesData.findCountByCustomQuery(entityManager, whereClause);
    	if (log.isTraceEnabled()) {
        	log.trace("<existsEndEntityProfileInRules("+profileid+"): "+count);
    	}
    	return count > 0;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCAInRules(Admin admin, int caid) {
        return existsCAInAdminGroups(caid) && existsCAInAccessRules(caid);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void forceRuleUpdate(Admin admin) {
        authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
        updateAuthorizationTree();
    }

    @Override
    public void flushAuthorizationRuleCache()  {
    	authCache.setAuthorizer(null);
    	if (log.isTraceEnabled()) {
    		log.trace(">flushAuthorizationRuleCache()");
    	}
    	updateAuthorizationTree();
    	if (log.isDebugEnabled()) {
    		log.debug("Flushed authorization cache.");
    	}    	
    	if (log.isTraceEnabled()) {
    		log.trace("<flushAuthorizationRuleCache()");
    	}
    }

    /**
     * Help function to existsCAInRules, checks if caid exists among entities in
     * admingroups.
     */
    private boolean existsCAInAdminGroups(int caid) {
    	if (log.isTraceEnabled()) {
            log.trace(">existsCAInAdminGroups("+caid+")");    		
    	}
        long count = AdminEntityData.findCountByCaId(entityManager, caid);
    	if (log.isTraceEnabled()) {
            log.trace("<existsCAInAdminGroups("+caid+"): "+count);
    	}
    	return count > 0;
    }

    /**
     * Help function to existsCAInRules, checks if caid exists among
     * accessrules.
     */
    private boolean existsCAInAccessRules(int caid) {
    	if (log.isTraceEnabled()) {
            log.trace(">existsCAInAccessRules("+caid+")");    		
    	}
    	String whereClause = "accessRule = '" + AccessRulesConstants.CABASE + "/" + caid + "' OR accessRule LIKE '" + AccessRulesConstants.CABASE + "/" + caid + "/%'";
        long count = AccessRulesData.findCountByCustomQuery(entityManager, whereClause);
    	if (log.isTraceEnabled()) {
            log.trace("<existsCAInAccessRules("+caid+"): "+count);
    	}
    	return count > 0;
    }

    /**
     * Method used check if a reconstruction of authorization tree is needed in
     * the authorization beans.
     * 
     * @return true if update is needed.
     */
    private boolean updateNeccessary() {
        boolean ret = false;
        // Only do the actual SQL query if we might update the configuration due to cache time anyhow
        if (authCache.needsUpdate()) {
            if (log.isDebugEnabled()) {
                log.debug("Checking if update neccessary");
            }
            ret = authorizationTreeUpdateDataSession.getAuthorizationTreeUpdateData().updateNeccessary(authCache.getAuthorizationTreeUpdateNumber());
            // we don't want to run the above query often
        }
        return ret;
    }

    /** Returns all the AdminGroups */
    private Collection<AdminGroup> getAdminGroups() {
        ArrayList<AdminGroup> returnval = new ArrayList<AdminGroup>();
        Iterator<AdminGroupData> iter = AdminGroupData.findAll(entityManager).iterator();
        while (iter.hasNext()) {
            returnval.add(iter.next().getAdminGroup());
        }
        return returnval;
    }
    
    /** method updating authorization tree. */
    private void updateAuthorizationTree() {
        if (log.isDebugEnabled()) {
            log.debug("updateAuthorizationTree");
        }
        // We must call getAuthorizer here, in order to make sure that we have the authorization cache updated with an 
        // authorizer object, otherwise we will get NullPointerException. 
        // Do not remove!
        getAuthorizer();
        int authorizationtreeupdatenumber = authorizationTreeUpdateDataSession.getAuthorizationTreeUpdateData().getAuthorizationTreeUpdateNumber();
        authCache.updateAuthorizationCache(getAdminGroups(), authorizationtreeupdatenumber);
    }
}
