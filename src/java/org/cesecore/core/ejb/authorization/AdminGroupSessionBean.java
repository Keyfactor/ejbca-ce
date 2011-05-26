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
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AdminEntitySessionLocal;
import org.ejbca.core.ejb.authorization.AdminGroupData;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
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
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AdminGroupSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminGroupSessionBean implements AdminGroupSessionLocal, AdminGroupSessionRemote{

    private final static Logger LOG = Logger.getLogger(AdminGroupSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    
    @EJB
    private LogSessionLocal logSession;
    @EJB
    private AuthorizationSessionLocal authSession;
    @EJB
    private AdminEntitySessionLocal admEntitySession;
    @EJB
    private AuthorizationTreeUpdateDataSessionLocal authTreeSession;
    
    @Override
    public void init(final Admin admin, final int caid, final String superAdminCN) throws AdminGroupExistsException {
        // Check if admingroup table is empty, if so insert default superuser
        // and create "special edit accessrules count group"
        final Collection<AdminGroupData> result = AdminGroupData.findAll(entityManager);
        if (result.isEmpty()) {     
            // Authorization table is empty, fill with default and special
            // admingroups.
            addAdminGroup(admin, AdminGroup.TEMPSUPERADMINGROUP);
            final ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
            adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, superAdminCN, caid));
            admEntitySession.addAdminEntities(admin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
            final ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
            accessrules.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
            addAccessRules(admin, AdminGroup.TEMPSUPERADMINGROUP, accessrules);
     
        }
        // Add Special Admin Group
        // Special admin group is a group that is not authenticated with client
        // certificate, such as batch tool etc
        if (AdminGroupData.findByGroupName(entityManager, AdminGroup.DEFAULTGROUPNAME) == null) {
            LOG.debug("initialize: FinderEx, add default group.");
            // Add Default Special Admin Group
            try {
                final AdminGroupData agdl = new AdminGroupData(Integer.valueOf(findFreeAdminGroupId()), AdminGroup.DEFAULTGROUPNAME);
                entityManager.persist(agdl);

                final ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_RAADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_INTERNALUSER));
                agdl.addAdminEntities(entityManager, adminentities);

                final ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
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

                authTreeSession.signalForAuthorizationTreeUpdate();
            } catch (Exception ce) {
                LOG.error("initialize continues after Exception: ", ce);
            }
        }
        // Add Public Web Group
        final AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, AdminGroup.PUBLICWEBGROUPNAME);
        if (agl == null) {
            LOG.debug("initialize: Can't find public web group");
            try {
                final AdminGroupData agdl = new AdminGroupData(Integer.valueOf(findFreeAdminGroupId()), AdminGroup.PUBLICWEBGROUPNAME);
                entityManager.persist(agdl);
                addDefaultPublicWebGroupRules(agdl);
                authTreeSession.signalForAuthorizationTreeUpdate();
            } catch (Exception ce) {
                LOG.error("initialize continues after Exception: ", ce);
            }
        } else {
            removeAndAddDefaultPublicWebGroupRules(agl);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<initialize, caid: " + caid);
        }
    
    }
   
    @Override
    public void addAccessRules(final Admin admin, final String admingroupname, final Collection<AccessRule> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                final AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.addAccessRules(entityManager, accessrules);
                authTreeSession.signalForAuthorizationTreeUpdate();
                final String msg = INTRES.getLocalizedMessage("authorization.accessrulesadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.erroraddaccessrules", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }
   
    @Override
    public void addAdminGroup(final Admin admin, final String admingroupname) throws AdminGroupExistsException {
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = false;
            if (AdminGroupData.findByGroupName(entityManager, admingroupname) == null) {
                try {
                    entityManager.persist(new AdminGroupData(Integer.valueOf(findFreeAdminGroupId()), admingroupname));
                    success = true;
                } catch (Exception e) {
                    final String msg = INTRES.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);
                    LOG.error(msg, e);
                }
            }
            if (success) {
                final String msg = INTRES.getLocalizedMessage("authorization.admingroupadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
                final String msg = INTRES.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
                throw new AdminGroupExistsException();
            }
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsAdministratorInGroup(final Admin admin, final int admingrouppk) {
        boolean returnval = false;
        final AdminGroupData agdl = AdminGroupData.findByPrimeKey(entityManager, Integer.valueOf(admingrouppk));
        if (agdl != null) {
            for(AdminEntity ae : agdl.getAdminGroup().getAdminEntities()) {     
                returnval = returnval || ae.match(admin.getAdminInformation());
            }
        }
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public AdminGroup getAdminGroup(final Admin admin, final String admingroupname) {
        AdminGroup returnval = null;
        final AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
        if (agd == null) {
            LOG.info("Can't get admingroup: " + admingroupname);
        } else {
            returnval = agd.getAdminGroup();
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<AdminGroup> getAuthorizedAdminGroupNames(final Admin admin, final Collection<Integer> availableCaIds) {
        final ArrayList<AdminGroup> returnval = new ArrayList<AdminGroup>();
        boolean issuperadmin = false;
    
        issuperadmin = authSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
     
        final HashSet<Integer> authorizedcaids = new HashSet<Integer>();
        final HashSet<Integer> allcaids = new HashSet<Integer>();
        if (!issuperadmin) {
            authorizedcaids.addAll(authSession.getAuthorizedCAIds(admin, availableCaIds));
            allcaids.addAll(availableCaIds);
        }

        final ArrayList<Integer> groupcaids = new ArrayList<Integer>();
        for (AdminGroupData agdl : AdminGroupData.findAll(entityManager)) {

            boolean allauthorized = false;
            boolean carecursive = false;
            boolean superadmingroup = false;
            boolean authtogroup = false;
            groupcaids.clear();
            if (!issuperadmin) {
                // Is admin authorized to all group caid. This is true if admin
                // is authorized to all CAs used by the different admins.
                final Collection<AdminEntity> admins = agdl.getAdminEntityObjects();
                final Iterator<AdminEntity> adminsIterator = admins.iterator();
                boolean onlyAuthCAIds = true;
                while (adminsIterator.hasNext()) {
                    final AdminEntity adminEntity = adminsIterator.next();
                    if (!authorizedcaids.contains(adminEntity.getCaId())) {
                        onlyAuthCAIds = false;
                        break;
                    }
                }
                if (onlyAuthCAIds) {
                    authtogroup = true;
                    // check access rules
                    final Iterator<AccessRule> iter = agdl.getAccessRuleObjects().iterator();
                    while (iter.hasNext()) {
                        final AccessRule accessrule = iter.next();
                        final String rule = accessrule.getAccessRule();
                        if (rule.equals(AccessRulesConstants.ROLE_SUPERADMINISTRATOR) && accessrule.getRule() == AccessRule.RULE_ACCEPT) {
                            superadmingroup = true;
                            break;
                        }
                        if (rule.equals(AccessRulesConstants.CABASE)) {
                            if (accessrule.getRule() == AccessRule.RULE_ACCEPT && accessrule.isRecursive() && authorizedcaids.containsAll(allcaids)) {
                            	carecursive = true;
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

    @Override
    public void removeAdminGroup(final Admin admin, final String admingroupname) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing admin group " + admingroupname);
        }
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            try {
                final AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agl == null) {
                    throw new FinderException("No Admin Group w name " + admingroupname);
                }
                removeEntitiesAndRulesFromGroup(agl);
                entityManager.remove(agl);
                authTreeSession.signalForAuthorizationTreeUpdate();

                final String msg = INTRES.getLocalizedMessage("authorization.admingroupremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.errorremoveadmingroup", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    @Override
    public void removeAccessRules(final Admin admin, final String admingroupname, final List<String> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                final AdminGroupData agd = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agd == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agd.removeAccessRules(entityManager, accessrules);
                authTreeSession.signalForAuthorizationTreeUpdate();
                final String msg = INTRES.getLocalizedMessage("authorization.accessrulesremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.errorremoveaccessrules", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    @Override
    public void replaceAccessRules(final Admin admin, final String admingroupname, final Collection<AccessRule> accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                final AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                final Collection<AccessRule> currentrules = agdl.getAdminGroup().getAccessRules();
                final ArrayList<String> removerules = new ArrayList<String>();
                final Iterator<AccessRule> iter = currentrules.iterator();
                while (iter.hasNext()) {
                    removerules.add(iter.next().getAccessRule());
                }
                agdl.removeAccessRules(entityManager, removerules);
                agdl.addAccessRules(entityManager, accessrules);
                authTreeSession.signalForAuthorizationTreeUpdate();
                final String msg = INTRES.getLocalizedMessage("authorization.accessrulesreplaced", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.errorreplaceaccessrules", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }
  
    @Override
    public void renameAdminGroup(final Admin admin, final String oldname, final String newname) throws AdminGroupExistsException {
        if (!(oldname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = false;
            AdminGroupData agl = AdminGroupData.findByGroupName(entityManager, newname);
            if (agl == null) {
                try {
                    agl = AdminGroupData.findByGroupName(entityManager, oldname);
                    if (agl == null) {
                        throw new FinderException("Cant find admin group w name " + oldname);
                    }
                    agl.setAdminGroupName(newname);
                    authTreeSession.signalForAuthorizationTreeUpdate();
                    success = true;
                } catch (Exception e) {
                    LOG.error("Can't rename admingroup: ", e);
                }
            } else {
                throw new AdminGroupExistsException();
            }
            if (success) {
            	final String msg = INTRES.getLocalizedMessage("authorization.admingrouprenamed", oldname, newname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
            	final String msg = INTRES.getLocalizedMessage("authorization.errorrenameadmingroup", oldname, newname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }
    
    private void addDefaultPublicWebGroupRules(final AdminGroupData agdl) {
        LOG.debug("create public web group");
        final ArrayList<AdminEntity> adminentities = new ArrayList<AdminEntity>();
        adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_PUBLICWEBUSER));
        agdl.addAdminEntities(entityManager, adminentities);

        final ArrayList<AccessRule> accessrules = new ArrayList<AccessRule>();
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
    	final Random random = new Random();
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
    
    private void removeEntitiesAndRulesFromGroup(final AdminGroupData agl) {
        LOG.debug("removing entities and rules for " + agl.getAdminGroupName());
        // Remove groups user entities.
        agl.removeAdminEntities(entityManager, agl.getAdminEntityObjects());

        // Remove groups accessrules.
        final Iterator<AccessRule> iter = agl.getAccessRuleObjects().iterator();
        final ArrayList<String> remove = new ArrayList<String>();
        while (iter.hasNext()) {
            remove.add(iter.next().getAccessRule());
        }
        agl.removeAccessRules(entityManager, remove);
    }

    private void removeAndAddDefaultPublicWebGroupRules(final AdminGroupData agl) {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Removing old and adding new accessrules and admin entitites to admin group " + agl.getAdminGroupName());
        }
        removeEntitiesAndRulesFromGroup(agl);
        addDefaultPublicWebGroupRules(agl);
        authTreeSession.signalForAuthorizationTreeUpdate();
    }
}
