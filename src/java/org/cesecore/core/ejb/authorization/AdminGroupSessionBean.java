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
package org.cesecore.core.ejb.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AdminGroupData;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * Handles AdminGroup entities. 
 * 
 * @version
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AdminGroupSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminGroupSessionBean implements AdminGroupSessionLocal, AdminGroupSessionRemote{

    private final static Logger log = Logger.getLogger(AdminGroupSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private AdminEntitySessionLocal adminEntitySession;
    @EJB 
    private AuthorizationTreeUpdateDataSessionRemote authorizationTreeUpdateDataSession;
    
    /**
     * Initializes this session bean manually, primarily for use from the CLI.
     * @throws AdminGroupExistsException 
     */
    public void init(Admin admin, int caid, String superAdminCN) throws AdminGroupExistsException {
        // Check if admingroup table is empty, if so insert default superuser
        // and create "special edit accessrules count group"
        Collection<AdminGroupData> result = AdminGroupData.findAll(entityManager);
        if (result.size() == 0) {     
            // Authorization table is empty, fill with default and special
            // admingroups.
            addAdminGroup(admin, AdminGroup.TEMPSUPERADMINGROUP);
            ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
            adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, superAdminCN, caid));
            adminEntitySession.addAdminEntities(admin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
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
                AdminGroupData agdl = new AdminGroupData(Integer.valueOf(findFreeAdminGroupId()), AdminGroup.DEFAULTGROUPNAME);
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

                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
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
                AdminGroupData agdl = new AdminGroupData(Integer.valueOf(findFreeAdminGroupId()), AdminGroup.PUBLICWEBGROUPNAME);
                entityManager.persist(agdl);
                addDefaultPublicWebGroupRules(agdl);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
            } catch (Exception ce) {
                log.error("initialize continues after Exception: ", ce);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<initialize, caid: " + caid);
        }
    
    }
   
    /**
     * Adds a Collection of AccessRule to an an admin group.
     * 
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
     * Method to add an admingroup.
     * 
     * @param admingroupname
     *            name of new admingroup, have to be unique.
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
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
     * Method to check if an administrator exists in the specified admingroup.
     * 
     * @return true if administrator exists in group
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk) {
        boolean returnval = false;
        /*
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        */
        AdminGroupData agdl = AdminGroupData.findByPrimeKey(entityManager, Integer.valueOf(admingrouppk));
        if (agdl != null) {
            for(AdminEntity ae : agdl.getAdminGroup().getAdminEntities()) {     
                returnval = returnval || ae.match(admin.getAdminInformation());
            }
        }
        return returnval;
    }
    
    /**
     * Method to get a reference to a admingroup.
     * 
     * @return The Admin group, null if it doesn't exist. 
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AdminGroup getAdminGroup(Admin admin, String admingroupname) {
        AdminGroup returnval = null;
        AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
        if (agd != null) {
            returnval = agd.getAdminGroup();
        } else {
            log.info("Can't get admingroup: " + admingroupname);
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
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<AdminGroup> getAuthorizedAdminGroupNames(Admin admin, Collection<Integer> availableCaIds) {
        ArrayList<AdminGroup> returnval = new ArrayList<AdminGroup>();
        boolean issuperadmin = false;
    
        issuperadmin = authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
     
        HashSet<Integer> authorizedcaids = new HashSet<Integer>();
        HashSet<Integer> allcaids = new HashSet<Integer>();
        if (!issuperadmin) {
            authorizedcaids.addAll(authorizationSession.getAuthorizedCAIds(admin, availableCaIds));
            allcaids.addAll(availableCaIds);
        }

        for (AdminGroupData agdl : AdminGroupData.findAll(entityManager)) {

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
                                groupcaids.add(Integer.valueOf(rule.substring(AccessRulesConstants.CAPREFIX.length())));
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
     * Method to remove a admingroup.
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
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();

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
    

    /**
     * Removes a Collection of (String) containing accessrules to remove from
     * admin group.
     * 
     */
    public void removeAccessRules(Admin admin, String admingroupname, List<String> accessrules) {
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
     * Method to rename a admingroup
     * 
     * @throws AdminGroupExistsException
     *             if admingroup already exists.
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
                    authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
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
     */
    private void removeAndAddDefaultPublicWebGroupRules(AdminGroupData agl) {
        if (log.isDebugEnabled()) {
            log.debug("Removing old and adding new accessrules and admin entitites to admin group " + agl.getAdminGroupName());
        }
        removeEntitiesAndRulesFromGroup(agl);
        addDefaultPublicWebGroupRules(agl);
        authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
    }
}
