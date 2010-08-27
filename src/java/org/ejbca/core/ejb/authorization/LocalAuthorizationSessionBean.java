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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.util.JDBCUtil;

/**
 * Stores data used by web server clients. Uses JNDI name for datasource as
 * defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @version $Id: LocalAuthorizationSessionBean.java 9579 2010-07-30 18:07:23Z
 *          jeklund $
 * 
 * @ejb.bean description="Session bean handling interface with ra authorization"
 *           display-name="AuthorizationSessionSB" name="AuthorizationSession"
 *           jndi-name="AuthorizationSession"
 *           local-jndi-name="AuthorizationSessionLocal" view-type="both"
 *           type="Stateless" transaction-type="Container"
 * 
 * @ejb.transaction type="Required"
 * 
 * @weblogic.enable-call-by-reference True
 * 
 * @ejb.env-entry name="DataSource" type="java.lang.String"
 *                value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 * 
 * @ejb.env-entry description=
 *                "Custom Available Access Rules, use ';' to separate multiple accessrules"
 *                name="CustomAvailableAccessRules" type="java.lang.String"
 *                value=""
 * 
 * @ejb.ejb-external-ref description="The log session bean" view-type="local"
 *                       ref-name="ejb/LogSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *                       business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *                       link="LogSession"
 * 
 * @ejb.ejb-external-ref description="Authorization Tree Update Bean"
 *                       view-type="local"
 *                       ref-name="ejb/AuthorizationTreeUpdateDataLocal"
 *                       type="Entity" home=
 *                       "org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateDataLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateDataLocal"
 *                       link="AuthorizationTreeUpdateData"
 * 
 * @ejb.ejb-external-ref description="Admin Groups" view-type="local"
 *                       ref-name="ejb/AdminGroupDataLocal" type="Entity"
 *                       home="org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.authorization.AdminGroupDataLocal"
 *                       link="AdminGroupData"
 * 
 * @ejb.home extends="javax.ejb.EJBHome" local-extends="javax.ejb.EJBLocalHome"
 *           local-class=
 *           "org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *           remote-class=
 *           "org.ejbca.core.ejb.authorization.IAuthorizationSessionHome"
 * 
 * @ejb.interface extends="javax.ejb.EJBObject"
 *                local-extends="javax.ejb.EJBLocalObject"
 *                local-class="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *                remote-class=
 *                "org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote"
 * 
 * @jonas.bean ejb-name="AuthorizationSession"
 * 
 * @jboss.method-attributes pattern = "get*" read-only = "true"
 * 
 * @jboss.method-attributes pattern = "is*" read-only = "true"
 * 
 * @jboss.method-attributes pattern = "exists*" read-only = "true"
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthorizationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LocalAuthorizationSessionBean implements AuthorizationSessionLocal, AuthorizationSessionRemote {

    private static final Logger log = Logger.getLogger(LocalAuthorizationSessionBean.class);
    private static final long serialVersionUID = 1L;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

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
     * 
     * @throws CreateException
     *             if bean instance can't be created
     */
    @PostConstruct
    public void ejbCreate() throws CreateException {
        log.trace(">ejbCreate()");
        ServiceLocator locator = ServiceLocator.getInstance();
        // TODO: Read from property file via commons config
        String customrules = locator.getString("java:comp/env/CustomAvailableAccessRules");
        if (customrules == null) {
            customrules = "";
        }
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
     * Method to initialize authorization bean, must be called directly after
     * creation of bean. Should only be called once.
     * 
     * @ejb.interface-method view-type="both"
     */
    public void initialize(Admin admin, int caid, String superAdminCN) throws AdminGroupExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">initialize, caid: " + caid + ", superAdminCN=" + superAdminCN);
        }
        // Check if admingroup table is empty, if so insert default superuser
        // and create "special edit accessrules count group"
        Collection<AdminGroupData> result = AdminGroupData.findAll(entityManager);
        if (result.size() == 0) {
            // Authorization table is empty, fill with default and special
            // admingroups.
            addAdminGroup(admin, AdminGroup.TEMPSUPERADMINGROUP);
            ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
            adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, superAdminCN, caid));
            addAdminEntities(admin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
            ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
            accessrules.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
            addAccessRules(admin, AdminGroup.TEMPSUPERADMINGROUP, accessrules);
        }
        // Add Special Admin Group
        // Special admin group is a group that is not authenticated with client
        // certificate, such as batch tool etc
        if (AdminGroupData.findByGroupName(entityManager, AdminGroup.DEFAULTGROUPNAME) == null) {
            log.debug("initialize: FinderEx, add default group.");
            // Add Default Special Admin Group
            try {
                AdminGroupData agdl = new AdminGroupData(new Integer(findFreeAdminGroupId()), AdminGroup.DEFAULTGROUPNAME);
                entityManager.persist(agdl);

                ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_RAADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_INTERNALUSER));
                agdl.addAdminEntities(entityManager, adminentities);

                ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
                accessrules.add(new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));

                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CAFUNCTIONALTY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_LOGFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.HARDTOKEN_HARDTOKENFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.CABASE, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT, true));

                agdl.addAccessRules(entityManager, accessrules);

                signalForAuthorizationTreeUpdate();
            } catch (Exception ce) {
                log.error("initialize continues after Exception: ", ce);
            }
        }
        // Add Public Web Group
        AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, AdminGroup.PUBLICWEBGROUPNAME);
        if (agl != null) {
            removeAndAddDefaultPublicWebGroupRules(agl);
        } else {
            log.debug("initialize: Can't find public web group");
            try {
                AdminGroupData agdl = new AdminGroupData(new Integer(findFreeAdminGroupId()), AdminGroup.PUBLICWEBGROUPNAME);
                entityManager.persist(agdl);
                addDefaultPublicWebGroupRules(agdl);
                signalForAuthorizationTreeUpdate();
            } catch (Exception ce) {
                log.error("initialize continues after Exception: ", ce);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<initialize, caid: " + caid);
        }
    }

    private void addDefaultPublicWebGroupRules(AdminGroupData agdl) {
        log.debug("create public web group");
        ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
        adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_PUBLICWEBUSER));
        agdl.addAdminEntities(entityManager, adminentities);

        ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
        accessrules.add(new AccessRule(AccessRulesConstants.ROLE_PUBLICWEBUSER, AccessRule.RULE_ACCEPT, false));

        accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CABASICFUNCTIONS, AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRule.RULE_ACCEPT, false));
        accessrules.add(new AccessRule(AccessRulesConstants.CABASE, AccessRule.RULE_ACCEPT, true));
        accessrules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT, true));

        agdl.addAccessRules(entityManager, accessrules);
    }

    /**
     */
    private void removeAndAddDefaultPublicWebGroupRules(AdminGroupData agl) {
        if (log.isDebugEnabled()) {
            log.debug("Removing old and adding new accessrules and admin entitites to admin group " + agl.getAdminGroupName());
        }
        removeEntitiesAndRulesFromGroup(agl);
        addDefaultPublicWebGroupRules(agl);
        signalForAuthorizationTreeUpdate();
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isGroupAuthorizedNoLog(int adminGroupId, String resource) throws AuthorizationDeniedException {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorizedNoLog(adminGroupId, resource);
    }

    /**
     * Method to check if an administrator exists in the specified admingroup.
     * 
     * @return true if administrator exists in group
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk) {
        boolean returnval = false;
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        AdminGroupData agdl = AdminGroupData.findByPrimeKey(entityManager, Integer.valueOf(admingrouppk));
        if (agdl != null) {
            Iterator<AdminEntity> adminentitites = agdl.getAdminGroup().getAdminEntities().iterator();
            while (adminentitites.hasNext()) {
                AdminEntity ae = adminentitites.next();
                returnval = returnval || ae.match(admin.getAdminInformation());
            }
        }
        return returnval;
    }

    /**
     * Method to add an admingroup.
     * 
     * @param admingroupname
     *            name of new admingroup, have to be unique.
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     * @ejb.interface-method view-type="both"
     */
    public void addAdminGroup(Admin admin, String admingroupname) throws AdminGroupExistsException {
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = false;
            if (AdminGroupData.findByGroupName(entityManager, admingroupname) == null) {
                try {
                    entityManager.persist(new AdminGroupData(new Integer(findFreeAdminGroupId()), admingroupname));
                    success = true;
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);
                    log.error(msg, e);
                }
            }
            if (success) {
                String msg = intres.getLocalizedMessage("authorization.admingroupadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
                String msg = intres.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
                throw new AdminGroupExistsException();
            }
        }
    }

    /**
     * Method to remove a admingroup.
     * 
     * @ejb.interface-method view-type="both"
     */
    public void removeAdminGroup(Admin admin, String admingroupname) {
        if (log.isDebugEnabled()) {
            log.debug("Removing admin group " + admingroupname);
        }
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            try {
                AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agl == null) {
                    throw new FinderException("No Admin Group w name " + admingroupname);
                }
                removeEntitiesAndRulesFromGroup(agl);
                entityManager.remove(agl);
                signalForAuthorizationTreeUpdate();

                String msg = intres.getLocalizedMessage("authorization.admingroupremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.errorremoveadmingroup", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    private void removeEntitiesAndRulesFromGroup(AdminGroupData agl) {
        log.debug("removing entities and rules for " + agl.getAdminGroupName());
        // Remove groups user entities.
        agl.removeAdminEntities(entityManager, agl.getAdminEntityObjects());

        // Remove groups accessrules.
        Iterator<AccessRule> iter = agl.getAccessRuleObjects().iterator();
        ArrayList<String> remove = new ArrayList<String>();
        while (iter.hasNext()) {
            remove.add(iter.next().getAccessRule());
        }
        agl.removeAccessRules(entityManager, remove);
    }

    /**
     * Method to rename a admingroup
     * 
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
     * @ejb.interface-method view-type="both"
     */
    public void renameAdminGroup(Admin admin, String oldname, String newname) throws AdminGroupExistsException {
        if (!(oldname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = false;
            AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, newname);
            if (agl != null) {
                throw new AdminGroupExistsException();
            } else {
                try {
                    agl = AdminGroupData.findByGroupName(entityManager, oldname);
                    if (agl == null) {
                        throw new FinderException("Cant find admin group w name " + oldname);
                    }
                    agl.setAdminGroupName(newname);
                    signalForAuthorizationTreeUpdate();
                    success = true;
                } catch (Exception e) {
                    log.error("Can't rename admingroup: ", e);
                }
            }
            if (success) {
                String msg = intres.getLocalizedMessage("authorization.admingrouprenamed", oldname, newname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
                String msg = intres.getLocalizedMessage("authorization.errorrenameadmingroup", oldname, newname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * Method to get a reference to a admingroup.
     * 
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroup getAdminGroup(Admin admin, String admingroupname) {
        AdminGroup returnval = null;
        AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
        if (agd != null) {
            returnval = agd.getAdminGroup();
        } else {
            log.error("Can't get admingroup: " + admingroupname);
        }
        return returnval;
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
     * Returns a Collection of AdminGroup the administrator is authorized to.
     * <p/>
     * SuperAdmin is authorized to all groups Other admins are only authorized
     * to the groups containing a subset of authorized CA that the admin himself
     * is authorized to.
     * <p/>
     * The AdminGroup objects only contains only name and caid and no accessdata
     * 
     * @param admin
     *            The current administrator
     * @param availableCaIds
     *            A Collection<Integer> of all CA Ids
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection getAuthorizedAdminGroupNames(Admin admin, Collection availableCaIds) {
        ArrayList<AdminGroup> returnval = new ArrayList<AdminGroup>();
        boolean issuperadmin = false;
        try {
            issuperadmin = this.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        } catch (AuthorizationDeniedException e1) {
        }
        HashSet<Integer> authorizedcaids = new HashSet<Integer>();
        HashSet<Integer> allcaids = new HashSet<Integer>();
        if (!issuperadmin) {
            authorizedcaids.addAll(getAuthorizer().getAuthorizedCAIds(admin, availableCaIds));
            allcaids.addAll(availableCaIds);
        }
        Collection<AdminGroupData> result = AdminGroupData.findAll(entityManager);
        Iterator<AdminGroupData> i = result.iterator();

        while (i.hasNext()) {
            AdminGroupData agdl = i.next();

            boolean allauthorized = false;
            boolean carecursive = false;
            boolean superadmingroup = false;
            boolean authtogroup = false;

            ArrayList<Integer> groupcaids = new ArrayList<Integer>();
            if (!issuperadmin) {
                // Is admin authorized to all group caid. This is true if admin
                // is authorized to all CAs used by the different admins.
                Collection<AdminEntity> admins = agdl.getAdminEntityObjects();
                Iterator<AdminEntity> adminsIterator = admins.iterator();
                boolean onlyAuthorizedCAIds = true;
                while (adminsIterator.hasNext()) {
                    AdminEntity adminEntity = adminsIterator.next();
                    if (!authorizedcaids.contains(adminEntity.getCaId())) {
                        onlyAuthorizedCAIds = false;
                        break;
                    }
                }
                if (onlyAuthorizedCAIds) {
                    authtogroup = true;
                    // check access rules
                    Iterator<AccessRule> iter = agdl.getAccessRuleObjects().iterator();
                    while (iter.hasNext()) {
                        AccessRule accessrule = iter.next();
                        String rule = accessrule.getAccessRule();
                        if (rule.equals(AccessRulesConstants.ROLE_SUPERADMINISTRATOR) && accessrule.getRule() == AccessRule.RULE_ACCEPT) {
                            superadmingroup = true;
                            break;
                        }
                        if (rule.equals(AccessRulesConstants.CABASE)) {
                            if (accessrule.getRule() == AccessRule.RULE_ACCEPT && accessrule.isRecursive()) {
                                if (authorizedcaids.containsAll(allcaids)) {
                                    carecursive = true;
                                }
                            }
                        } else {
                            if (rule.startsWith(AccessRulesConstants.CAPREFIX) && accessrule.getRule() == AccessRule.RULE_ACCEPT) {
                                groupcaids.add(new Integer(rule.substring(AccessRulesConstants.CAPREFIX.length())));
                            }
                        }
                    }
                }
            }
            allauthorized = authorizedcaids.containsAll(groupcaids);

            if (issuperadmin || ((allauthorized || carecursive) && authtogroup && !superadmingroup)) {
                if (!agdl.getAdminGroupName().equals(AdminGroup.PUBLICWEBGROUPNAME) && !(agdl.getAdminGroupName().equals(AdminGroup.DEFAULTGROUPNAME))) {
                    returnval.add(agdl.getAdminGroupNames());
                }
            }
        }
        return returnval;
    }

    /**
     * Adds a Collection of AccessRule to an an admin group.
     * 
     * @ejb.interface-method view-type="both"
     */
    public void addAccessRules(Admin admin, String admingroupname, Collection accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.addAccessRules(entityManager, accessrules);
                signalForAuthorizationTreeUpdate();
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
     * @ejb.interface-method view-type="both"
     */
    public void removeAccessRules(Admin admin, String admingroupname, Collection accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.removeAccessRules(entityManager, accessrules);
                signalForAuthorizationTreeUpdate();
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
     * 
     * @ejb.interface-method view-type="both"
     */
    public void replaceAccessRules(Admin admin, String admingroupname, Collection accessrules) {
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
                signalForAuthorizationTreeUpdate();
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
     * Adds a Collection of AdminEnity to the admingroup. Changes their values
     * if they already exists.
     * 
     * @ejb.interface-method view-type="both"
     */

    public void addAdminEntities(Admin admin, String admingroupname, Collection adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agdl.addAdminEntities(entityManager, adminentities);
                signalForAuthorizationTreeUpdate();
                String msg = intres.getLocalizedMessage("authorization.adminadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.erroraddadmin", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * Removes a Collection of AdminEntity from the administrator group.
     * 
     * @ejb.interface-method view-type="both"
     */
    public void removeAdminEntities(Admin admin, String admingroupname, Collection adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agdl.removeAdminEntities(entityManager, adminentities);
                signalForAuthorizationTreeUpdate();
                String msg = intres.getLocalizedMessage("authorization.adminremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("authorization.errorremoveadmin", admingroupname);
                log.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    /**
     * @throws AuthorizationDeniedException
     *             if administrator isn't authorized to all issuers of the admin
     *             certificates in this group
     * 
     * @ejb.interface-method view-type="both"
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection getAuthorizedAvailableAccessRules(Admin admin, Collection availableCaIds, boolean enableendentityprofilelimitations,
            boolean usehardtokenissuing, boolean usekeyrecovery, Collection authorizedEndEntityProfileIds, Collection authorizedUserDataSourceIds) {
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
     * 
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection getAuthorizedCAIds(Admin admin, Collection availableCaIds) {
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
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection availableEndEntityProfileId) {
        return getAuthorizer().getAuthorizedEndEntityProfileIds(admin, rapriviledge, availableEndEntityProfileId);
    }

    /**
     * Method to check if an end entity profile exists in any end entity profile
     * rules. Used to avoid desyncronization of profilerules.
     * 
     * @param profileid
     *            the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid) {
        log.trace(">existsEndEntityProfileInRules()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        String whereclause = "accessRule  LIKE '" + AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + "%'";

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from AccessRulesData where " + whereclause);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            log.trace("<existsEndEntityProfileInRules()");
            return count > 0;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid
     * desyncronization of CA rules when ca is removed
     * 
     * @param caid
     *            the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsCAInRules(Admin admin, int caid) {
        return existsCAInAdminGroups(caid) && existsCAInAccessRules(caid);
    }

    /**
     * Method to force an update of the autorization rules without any wait.
     * 
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void forceRuleUpdate(Admin admin) {
        signalForAuthorizationTreeUpdate();
        updateAuthorizationTree();
    }

    /**
     * Help function to existsCAInRules, checks if caid axists among entities in
     * admingroups.
     */
    private boolean existsCAInAdminGroups(int caid) {
        log.trace(">existsCAInAdminGroups()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.
        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from AdminEntityData where cAId = ?");
            ps.setInt(1, caid);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            boolean exists = count > 0;
            log.trace("<existsCAInAdminGroups(): " + exists);
            return exists;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Help function to existsCAInRules, checks if caid axists among
     * accessrules.
     */
    private boolean existsCAInAccessRules(int caid) {
        log.trace(">existsCAInAccessRules()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        String whereclause = "accessRule  LIKE '" + AccessRulesConstants.CABASE + "/" + caid + "%'";

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from AccessRulesData where " + whereclause);
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            boolean exists = count > 0;
            log.trace("<existsCAInAccessRules(): " + exists);
            return exists;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Cache this local bean, because it will cause many many database lookups
     * otherwise
     */
    private AuthorizationTreeUpdateData atu = null;

    /**
     * Returns a reference to the AuthorizationTreeUpdateData
     */
    private AuthorizationTreeUpdateData getAuthorizationTreeUpdateData() {
        if (atu == null) {
            atu = AuthorizationTreeUpdateData.findByPrimeKey(entityManager, AuthorizationTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
            if (atu == null) {
                try {
                    AuthorizationTreeUpdateData temp = new AuthorizationTreeUpdateData();
                    entityManager.persist(temp);
                    atu = temp;
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("authorization.errorcreateauthtree");
                    log.error(msg, e);
                    throw new EJBException(e);
                }
            }
        }
        return atu;
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
            ret = getAuthorizationTreeUpdateData().updateNeccessary(authorizationtreeupdate);
            lastupdatetime = System.currentTimeMillis(); 
            // we don't want to run the above query often
        }
        return ret;
    }

    /**
     * method updating authorization tree.
     */
    private void updateAuthorizationTree() {
        if (log.isDebugEnabled()) {
            log.debug("updateAuthorizationTree");
        }
        getAuthorizer().buildAccessTree(getAdminGroups());
        authorizationtreeupdate = getAuthorizationTreeUpdateData().getAuthorizationTreeUpdateNumber();
        lastupdatetime = System.currentTimeMillis();
    }

    /**
     * Method incrementing the authorizationtreeupdatenumber and thereby
     * signaling to other beans that they should reconstruct their accesstrees.
     */
    private void signalForAuthorizationTreeUpdate() {
    	if (log.isTraceEnabled()) {
    		log.trace(">signalForAuthorizationTreeUpdate");
    	}
        getAuthorizationTreeUpdateData().incrementAuthorizationTreeUpdateNumber();
    	if (log.isTraceEnabled()) {
    		log.trace("<signalForAuthorizationTreeUpdate");
    	}
    }

    private int findFreeAdminGroupId() {
        Random random = new Random();
        int id = random.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
            if (AdminGroupData.findByPrimeKey(entityManager, Integer.valueOf(id)) == null) {
                foundfree = true;
            }
            id = random.nextInt();
        }
        return id;
    }
}
