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

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.authorization.AuthorizationTreeUpdateDataSessionRemote;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.ConfigurationHolder;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupDoesNotExistException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * Stores data used by web server clients. Uses JNDI name for datasource as
 * defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthorizationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthorizationSessionBean implements AuthorizationSessionLocal, AuthorizationSessionRemote {

    private static final Logger log = Logger.getLogger(AuthorizationSessionBean.class);
    private static final long serialVersionUID = 1L;

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationTreeUpdateDataSessionRemote authorizationTreeUpdateDataSession;
    
    @EJB
    private LogSessionLocal logSession;

    /** Cache for authorization data */
    private static final AuthorizationCache authCache = new AuthorizationCache();
    
    private String[] customaccessrules = null;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     */
    @PostConstruct
    public void ejbCreate() {
    	if (log.isTraceEnabled()) {
            log.trace(">ejbCreate()");    		
    	}
        String customrules = ConfigurationHolder.getString("ejbca.customavailableaccessaules", "");
        customaccessrules = StringUtils.split(customrules, ';');
    	if (log.isTraceEnabled()) {
    		log.trace("<ejbCreate()");
    	}
    }

    private Authorizer getAuthorizer() {
        if (authCache.getAuthorizer() == null) {
            authCache.setAuthorizer(new Authorizer(getAdminGroups(), logSession, LogConstants.MODULE_AUTHORIZATION));
        }
        return authCache.getAuthorizer();
    }


    /**
     * Method to check if a user is authorized to a certain resource.
     * 
     * @param admin
     *            the administrator about to be authorized, see
     *            org.ejbca.core.model.log.Admin class.
     * @param resource
     *            the resource to check authorization for.
     * @return true if authorized
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorized(Admin admin, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isAuthorized(admin, resource);
    }

    /**
     * Method to check if a user is authorized to a certain resource without
     * performing any logging.
     * 
     * @param admin
     *            the administrator about to be authorized, see
     *            org.ejbca.core.model.log.Admin class.
     * @param resource
     *            the resource to check authorization for.
     * @return true if authorized, but not false if not authorized, throws
     *         exception instead so return value can safely be ignored.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isAuthorizedNoLog(Admin admin, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isAuthorizedNoLog(admin, resource);
    }

    /**
     * Method to check if a group is authorized to a resource.
     * 
     * @return true if authorized
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorized(admin, adminGroupId, resource);
    }

    /**
     * Method to check if a group is authorized to a resource without any
     * logging.
     * 
     * @return true if authorized
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorizedNoLog(adminGroupId, resource);
    }



    /**
     * Checks that the given Admin is authorized to all CAs in the given group. Will return true if the group is empty.
     * 
     * @param administrator Admin token to check
     * @param admingroupname Name of group to check in.
     * 
     * @throws AdminGroupDoesNotExistException
     *             if the admin group doesn't exist.
     */
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

    /**
     * Method used to collect an administrators available access rules based on
     * which rule he himself is authorized to.
     * 
     * @param admin
     *            is the administrator calling the method.
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     * @param enableendentityprofilelimitations
     *            Include End Entity Profile access rules
     * @param usehardtokenissuing
     *            Include Hard Token access rules
     * @param usekeyrecovery
     *            Include Key Recovery access rules
     * @param authorizedEndEntityProfileIds
     *            A Collection<Integer> of all auhtorized End Entity Profile ids
     * @param authorizedUserDataSourceIds
     *            A Collection<Integer> of all auhtorized user data sources ids
     * @return a Collection of String containing available accessrules.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<String> getAuthorizedAvailableAccessRules(Admin admin, Collection<Integer> availableCaIds, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection<Integer> authorizedEndEntityProfileIds, Collection<Integer> authorizedUserDataSourceIds) {
        AvailableAccessRules availableAccessRules = new AvailableAccessRules(admin, getAuthorizer(), customaccessrules, availableCaIds,
                enableendentityprofilelimitations, usehardtokenissuing, usekeyrecovery);
        return availableAccessRules.getAvailableAccessRules(admin, authorizedEndEntityProfileIds, authorizedUserDataSourceIds);
    }

    /**
     * Method used to return an Collection of Integers indicating which CAids a
     * administrator is authorized to access.
     * 
     * @param admin
     *            The current administrator
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     * @return Collection of Integer
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<Integer> getAuthorizedCAIds(Admin admin, Collection<Integer> availableCaIds) {
        return getAuthorizer().getAuthorizedCAIds(admin, availableCaIds);
    }

    /**
     * Method used to return an Collection of Integers indicating which end
     * entity profiles the administrator is authorized to view.
     * 
     * @param admin
     *            the administrator
     * @param rapriviledge
     *            should be one of the end entity profile authorization constans
     *            defined in AccessRulesConstants.
     * @param authorizedEndEntityProfileIds
     *            A Collection<Integer> of all auhtorized EEP ids
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection<Integer> availableEndEntityProfileId) {
        return getAuthorizer().getAuthorizedEndEntityProfileIds(admin, rapriviledge, availableEndEntityProfileId);
    }

    /**
     * Method to check if an end entity profile exists in any end entity profile
     * rules. Used to avoid desyncronization of profilerules.
     * 
     * @param profileid
     *            the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid) {
    	if (log.isTraceEnabled()) {
        	log.trace(">existsEndEntityProfileInRules("+profileid+")");    		
    	}
        String whereClause = "accessRule  LIKE '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "%'";
        long count = AccessRulesData.findCountByCustomQuery(entityManager, whereClause);
    	if (log.isTraceEnabled()) {
        	log.trace("<existsEndEntityProfileInRules("+profileid+"): "+count);
    	}
    	return count > 0;
    }

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid
     * desyncronization of CA rules when ca is removed
     * 
     * @param caid
     *            the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsCAInRules(Admin admin, int caid) {
        return existsCAInAdminGroups(caid) && existsCAInAccessRules(caid);
    }

    /**
     * Method to force an update of the authorization rules without any wait.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void forceRuleUpdate(Admin admin) {
        authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
        updateAuthorizationTree();
    }

    /**
     * Clear and load authorization rules cache.
     */
    public void flushAuthorizationRuleCache()  {
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
        String whereClause = "accessRule LIKE '" + AccessRulesConstants.CABASE + "/" + caid + "%'";
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

    /**
     * Returns all the AdminGroups
     */
    private Collection<AdminGroup> getAdminGroups() {
        ArrayList<AdminGroup> returnval = new ArrayList<AdminGroup>();
        Iterator<AdminGroupData> iter = AdminGroupData.findAll(entityManager).iterator();
        while (iter.hasNext()) {
            returnval.add(iter.next().getAdminGroup());
        }
        return returnval;
    }
    
    /**
     * method updating authorization tree.
     */
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
