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
import java.util.Iterator;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.FinderException;
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
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
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

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationTreeUpdateDataSessionRemote authorizationTreeUpdateDataSession;
    
    @EJB
    private LogSessionLocal logSession;

    /** Cache for authorization data */
    private static volatile Authorizer authorizer = null;

    /**
     * help variable used to check that authorization trees are updated.
     */
    private static volatile int authorizationtreeupdate = -1;
    /**
     * help variable used to control that update isn't performed to often.
     */
    private static volatile long lastupdatetime = -1;


    private String[] customaccessrules = null;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     */
    @PostConstruct
    public void ejbCreate() {
        log.trace(">ejbCreate()");
        String customrules = ConfigurationHolder.getString("ejbca.customavailableaccessaules", "");
        customaccessrules = StringUtils.split(customrules, ';');
        log.trace("<ejbCreate()");
    }

    private Authorizer getAuthorizer() {
        if (authorizer == null) {
            authorizer = new Authorizer(getAdminGroups(), logSession, LogConstants.MODULE_AUTHORIZATION);
        }
        return authorizer;
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
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException {
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
    public boolean isAuthorizedNoLog(Admin admin, String resource) throws AuthorizationDeniedException {
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
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource) throws AuthorizationDeniedException {
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
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) throws AuthorizationDeniedException {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorizedNoLog(adminGroupId, resource);
    }






    /**
     * Adds a Collection of AccessRule to an an admin group.
     */
    public void addAccessRules(Admin admin, String admingroupname, Collection<AccessRule> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.addAccessRules(entityManager, accessrules);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
                String msg = intres.getLocalizedMessage("authorization.accessrulesadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.erroraddaccessrules", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * Removes a Collection of (String) containing accessrules to remove from
     * admin group.
     * 
     */
    public void removeAccessRules(Admin admin, String admingroupname, Collection<String> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.removeAccessRules(entityManager, accessrules);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
                String msg = intres.getLocalizedMessage("authorization.accessrulesremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.errorremoveaccessrules", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * Replaces a groups accessrules with a new set of rules
     */
    public void replaceAccessRules(Admin admin, String admingroupname, Collection<AccessRule> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                Collection<AccessRule> currentrules = agdl.getAdminGroup().getAccessRules();
                ArrayList<String> removerules = new ArrayList<String>();
                Iterator<AccessRule> iter = currentrules.iterator();
                while (iter.hasNext()) {
                    removerules.add(iter.next().getAccessRule());
                }
                agdl.removeAccessRules(entityManager, removerules);
                agdl.addAccessRules(entityManager, accessrules);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
                String msg = intres.getLocalizedMessage("authorization.accessrulesreplaced", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.errorreplaceaccessrules", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to all issuers of the admin
     *             certificates in this group
     */
    public void isAuthorizedToGroup(Admin administrator, String admingroupname) throws AuthorizationDeniedException {
        ArrayList<Integer> al = new ArrayList<Integer>();
        AdminGroupData adminGroupData = AdminGroupData.findByGroupName(entityManager, admingroupname);
        if (adminGroupData != null) {
            Iterator<AdminEntity> i = adminGroupData.getAdminEntityObjects().iterator();
            while (i.hasNext()) {
                int currentCaId = i.next().getCaId();
                if (!al.contains(currentCaId)) {
                    isAuthorizedNoLog(administrator, AccessRulesConstants.CAPREFIX + currentCaId);
                    al.add(currentCaId);
                }
            }
        } else {
            log.error("Could not find admin group " + admingroupname);
        }
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
        log.trace(">existsEndEntityProfileInRules()");
        String whereClause = "accessRule  LIKE '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "%'";
        return AccessRulesData.findCountByCustomQuery(entityManager, whereClause) > 0;
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
     * Help function to existsCAInRules, checks if caid axists among entities in
     * admingroups.
     */
    private boolean existsCAInAdminGroups(int caid) {
        log.trace(">existsCAInAdminGroups()");
        return AdminEntityData.findCountByCaId(entityManager, caid) > 0;
    }

    /**
     * Help function to existsCAInRules, checks if caid axists among
     * accessrules.
     */
    private boolean existsCAInAccessRules(int caid) {
        log.trace(">existsCAInAccessRules()");
        String whereClause = "accessRule LIKE '" + AccessRulesConstants.CABASE + "/" + caid + "%'";
        return AccessRulesData.findCountByCustomQuery(entityManager, whereClause) > 0;
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
        if (lastupdatetime < (System.currentTimeMillis() - EjbcaConfiguration.getCacheAuthorizationTime())) {
            if (log.isDebugEnabled()) {
                log.debug("Checking if update neccessary");
            }
            ret = authorizationTreeUpdateDataSession.getAuthorizationTreeUpdateData().updateNeccessary(authorizationtreeupdate);
            lastupdatetime = System.currentTimeMillis(); 
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
        getAuthorizer().buildAccessTree(getAdminGroups());
        authorizationtreeupdate = authorizationTreeUpdateDataSession.getAuthorizationTreeUpdateData().getAuthorizationTreeUpdateNumber();
        lastupdatetime = System.currentTimeMillis();
    }



}
