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

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
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
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 *
 * @ejb.bean
 *   description="Session bean handling interface with ra authorization"
 *   display-name="AuthorizationSessionSB"
 *   name="AuthorizationSession"
 *   jndi-name="AuthorizationSession"
 *   local-jndi-name="AuthorizationSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.env-entry
 *   description="Custom Available Access Rules, use ';' to separate multiple accessrules"
 *   name="CustomAvailableAccessRules"
 *   type="java.lang.String"
 *   value=""
 *
 * @ejb.ejb-external-ref
 *   description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref
 *   description="Authorization Tree Update Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationTreeUpdateDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateDataLocalHome"
 *   business="org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateDataLocal"
 *   link="AuthorizationTreeUpdateData"
 *
 * @ejb.ejb-external-ref
 *   description="Admin Groups"
 *   view-type="local"
 *   ref-name="ejb/AdminGroupDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome"
 *   business="org.ejbca.core.ejb.authorization.AdminGroupDataLocal"
 *   link="AdminGroupData"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.authorization.IAuthorizationSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   remote-class="org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote"
 *
 * @jonas.bean
 *   ejb-name="AuthorizationSession"
 *   
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *
 * @jboss.method-attributes
 *   pattern = "is*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "exists*"
 *   read-only = "true"
 *   
 */
public class LocalAuthorizationSessionBean extends BaseSessionBean {

    /**
     * Constant indicating minimum time between updates. In milliseconds, 30 seconds.
     */
    private static final long MIN_TIME_BETWEEN_UPDATES = 30000;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * The home interface of  AdminGroupData entity bean
     */
    private AdminGroupDataLocalHome admingrouphome = null;

    /**
     * The home interface of AuthorizationTreeUpdateData entity bean
     */
    private AuthorizationTreeUpdateDataLocalHome authorizationtreeupdatehome = null;

    /**
     * help variable used to check that authorization trees is updated.
     */
    private int authorizationtreeupdate = -1;

    /**
     * help variable used to control that update isn't performed to often.
     */
    private long lastupdatetime = -1;

    /**
     * The local interface of  log session bean
     */
    private ILogSessionLocal logsession = null;

    private Authorizer authorizer = null;

    private String[] customaccessrules = null;


    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        trace(">ejbCreate()");
        ServiceLocator locator = ServiceLocator.getInstance();
        admingrouphome = (AdminGroupDataLocalHome) locator.getLocalHome(AdminGroupDataLocalHome.COMP_NAME);
        authorizationtreeupdatehome = (AuthorizationTreeUpdateDataLocalHome) locator.getLocalHome(AuthorizationTreeUpdateDataLocalHome.COMP_NAME);
        String customrules = locator.getString("java:comp/env/CustomAvailableAccessRules");
        if (customrules == null) {
        	customrules = "";
        } 
        customaccessrules = StringUtils.split(customrules, ';');
        trace("<ejbCreate()");
    }
    
    private Authorizer getAuthorizer() {
    	if (authorizer == null) {
            authorizer = new Authorizer(getAdminGroups(), admingrouphome, getLogSession(), LogConstants.MODULE_AUTHORIZATION);
    	}
    	return authorizer;
    }


    /**
     * Gets connection to log session bean
     *
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession

    // Methods used with AdminGroupData Entity Beans

    /**
     * Method to initialize authorization bean, must be called directly after creation of bean. Should only be called once.
     *
     * @ejb.interface-method view-type="both"
     */
    public void initialize(Admin admin, int caid) throws AdminGroupExistsException {
    	if (log.isTraceEnabled()) {
    		log.trace(">initialize, caid: "+caid);
    	}
        // Check if admingroup table is empty, if so insert default superuser
        // and create "special edit accessrules count group"
        try {
            Collection result = admingrouphome.findAll();
            if (result.size() == 0) {
                // Authorization table is empty, fill with default and special admingroups.
                addAdminGroup(admin, AdminGroup.TEMPSUPERADMINGROUP);
                ArrayList adminentities = new ArrayList();
                adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, "SuperAdmin", caid));
                addAdminEntities(admin, AdminGroup.TEMPSUPERADMINGROUP, adminentities);
                ArrayList accessrules = new ArrayList();
                accessrules.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
                addAccessRules(admin, AdminGroup.TEMPSUPERADMINGROUP, accessrules);
            }
        } catch (FinderException e) {
        	debug("initialize: FinderEx, findAll failed.");
        }
        // Add Special Admin Group
        // Special admin group is a group that is not authenticated with client certificate, such as batch tool etc
        try {
            admingrouphome.findByGroupName(AdminGroup.DEFAULTGROUPNAME);
        } catch (FinderException e) {
        	debug("initialize: FinderEx, add default group.");
            // Add Default Special Admin Group
            try {
                AdminGroupDataLocal agdl = admingrouphome.create(new Integer(findFreeAdminGroupId()), AdminGroup.DEFAULTGROUPNAME);

                ArrayList adminentities = new ArrayList();
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_BATCHCOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_CACOMMANDLINEADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_RAADMIN));
                adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_INTERNALUSER));
                agdl.addAdminEntities(adminentities);

                ArrayList accessrules = new ArrayList();
                accessrules.add(new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));

                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CAFUNCTIONALTY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_LOGFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.HARDTOKEN_HARDTOKENFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.CABASE, AccessRule.RULE_ACCEPT, true));
                accessrules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT, true));

                agdl.addAccessRules(accessrules);

                signalForAuthorizationTreeUpdate();
            } catch (CreateException ce) {
            	error("initialize continues after Exception: ", ce);
            }
        }
        // Add Public Web Group
        try {
            AdminGroupDataLocal agl = admingrouphome.findByGroupName(AdminGroup.PUBLICWEBGROUPNAME);
            removeAndAddDefaultPublicWebGroupRules(agl);
        } catch (FinderException e) {
        	debug("initialize: FinderEx, can't find public web group");
        	try {
                AdminGroupDataLocal agdl = admingrouphome.create(new Integer(findFreeAdminGroupId()), AdminGroup.PUBLICWEBGROUPNAME);
                addDefaultPublicWebGroupRules(agdl);
                signalForAuthorizationTreeUpdate();
            } catch (CreateException ce) {
            	error("initialize continues after Exception: ", ce);
            }
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<initialize, caid: "+caid);
    	}
    }


	private void addDefaultPublicWebGroupRules(AdminGroupDataLocal agdl) {
    	debug("create public web group");
		ArrayList adminentities = new ArrayList();
		adminentities.add(new AdminEntity(AdminEntity.SPECIALADMIN_PUBLICWEBUSER));
		agdl.addAdminEntities(adminentities);

		ArrayList accessrules = new ArrayList();
		accessrules.add(new AccessRule(AccessRulesConstants.ROLE_PUBLICWEBUSER, AccessRule.RULE_ACCEPT, false));

		accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CABASICFUNCTIONS, AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRule.RULE_ACCEPT, false));
		accessrules.add(new AccessRule(AccessRulesConstants.CABASE, AccessRule.RULE_ACCEPT, true));
		accessrules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT, true));

		agdl.addAccessRules(accessrules);
	}


    /**
     */
    private void removeAndAddDefaultPublicWebGroupRules(AdminGroupDataLocal agl) {
    	if (log.isDebugEnabled()) {
    		debug("Removing old and adding new accessrules and admin entitites to admin group "+agl.getAdminGroupName());
    	}
        removeEntitiesAndRulesFromGroup(agl);
        addDefaultPublicWebGroupRules(agl);
        signalForAuthorizationTreeUpdate();
    }

    /**
     * Method to check if a user is authorized to a certain resource.
     *
     * @param admin    the administrator about to be authorized, see org.ejbca.core.model.log.Admin class.
     * @param resource the resource to check authorization for.
     * @return true if authorized
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public boolean isAuthorized(Admin admin, String resource) throws AuthorizationDeniedException {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isAuthorized(admin, resource);
    }

    /**
     * Method to check if a user is authorized to a certain resource without performing any logging.
     *
     * @param admin    the administrator about to be authorized, see org.ejbca.core.model.log.Admin class.
     * @param resource the resource to check authorization for.
     * @return true if authorized
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
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
    public boolean isGroupAuthorized(Admin admin, int adminGroupId, String resource) throws AuthorizationDeniedException {
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorized(admin, adminGroupId, resource);
    }

    /**
     * Method to check if a group is authorized to a resource without any logging.
     *
     * @return true if authorized
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public boolean isGroupAuthorizedNoLog(Admin admin, int adminGroupId, String resource) throws AuthorizationDeniedException {
        if (updateNeccessary()) {
        	updateAuthorizationTree();
        }
        return getAuthorizer().isGroupAuthorizedNoLog(admin, adminGroupId, resource);
    }

    /**
     * Method to check if an administrator exists in the specified admingroup.
     *
     * @return true if administrator exists in group
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public boolean existsAdministratorInGroup(Admin admin, int admingrouppk) {
        boolean returnval = false;
        if (updateNeccessary()) {
            updateAuthorizationTree();
        }
        try {
            AdminGroupDataLocal agdl = admingrouphome.findByPrimaryKey(new Integer(admingrouppk));
            Iterator adminentitites = agdl.getAdminGroup().getAdminEntities().iterator();
            while (adminentitites.hasNext()) {
                AdminEntity ae = (AdminEntity) adminentitites.next();
                returnval = returnval || ae.match(admin.getAdminInformation());
            }
        } catch (FinderException fe) {
        }

        return returnval;
    }

    /**
     * Method to add an admingroup.
     *
     * @param admingroupname name of new admingroup, have to be unique.
     * @throws AdminGroupExistsException if admingroup already exists.
     * @ejb.interface-method view-type="both"
     */
    public void addAdminGroup(Admin admin, String admingroupname) throws AdminGroupExistsException {
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = true;
            try {
                admingrouphome.findByGroupName(admingroupname);
                success = false;
            } catch (FinderException e) {
            }
            if (success) {
                try {
                    admingrouphome.create(new Integer(findFreeAdminGroupId()), admingroupname);
                    success = true;
                } catch (CreateException e) {
            		String msg = intres.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);            	
                    error(msg, e);
                    success = false;
                }
            }
            if (success) {
        		String msg = intres.getLocalizedMessage("authorization.admingroupadded", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
        		String msg = intres.getLocalizedMessage("authorization.erroraddadmingroup", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
                throw new AdminGroupExistsException();
            }
        }
    } // addAdminGroup

    /**
     * Method to remove a admingroup.
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeAdminGroup(Admin admin, String admingroupname) {
    	if (log.isDebugEnabled()) {
    		debug("Removing admin group "+admingroupname);
    	}
        if (!(admingroupname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            try {
                AdminGroupDataLocal agl = admingrouphome.findByGroupName(admingroupname);
                removeEntitiesAndRulesFromGroup(agl);

                agl.remove();
                signalForAuthorizationTreeUpdate();

        		String msg = intres.getLocalizedMessage("authorization.admingroupremoved", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.errorremoveadmingroup", admingroupname);            	
                error(msg, e);
                getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // removeAdminGroup


	private void removeEntitiesAndRulesFromGroup(AdminGroupDataLocal agl) {
    	debug("removing entities and rules for "+agl.getAdminGroupName());
		// Remove groups user entities.
		agl.removeAdminEntities(agl.getAdminEntityObjects());

		// Remove groups accessrules.
		Iterator iter = agl.getAccessRuleObjects().iterator();
		ArrayList remove = new ArrayList();
		while (iter.hasNext()) {
		    remove.add(((AccessRule) iter.next()).getAccessRule());
		}
		agl.removeAccessRules(remove);
	}

    /**
     * Metod to rename a admingroup
     *
     * @throws AdminGroupExistsException if admingroup already exists.
     * @ejb.interface-method view-type="both"
     */
    public void renameAdminGroup(Admin admin, String oldname, String newname) throws AdminGroupExistsException {
        if (!(oldname.equals(AdminGroup.DEFAULTGROUPNAME))) {
            boolean success = false;
            AdminGroupDataLocal agl = null;
            try {
                agl = admingrouphome.findByGroupName(newname);
                throw new AdminGroupExistsException();
            } catch (FinderException e) {
                success = true;
            }
            if (success) {
                try {
                    agl = admingrouphome.findByGroupName(oldname);
                    agl.setAdminGroupName(newname);
                    signalForAuthorizationTreeUpdate();
                } catch (Exception e) {
                    error("Can't rename admingroup: ", e);
                    success = false;
                }
            }

            if (success) {
        		String msg = intres.getLocalizedMessage("authorization.admingrouprenamed", oldname, newname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } else {
        		String msg = intres.getLocalizedMessage("authorization.errorrenameadmingroup", oldname, newname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);            	
            }
        }
    } // renameAdminGroup


    /**
     * Method to get a reference to a admingroup.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */

    public AdminGroup getAdminGroup(Admin admin, String admingroupname) {
        AdminGroup returnval = null;
        try {
            returnval = (admingrouphome.findByGroupName(admingroupname)).getAdminGroup();
        } catch (Exception e) {
            error("Can't get admingroup: ", e);
        }
        return returnval;
    } // getAdminGroup


    /**
     * Returns the total number of admingroups
     */
    private Collection getAdminGroups() {
        ArrayList returnval = new ArrayList();
        try {
            Iterator iter = admingrouphome.findAll().iterator();
            while (iter.hasNext()) {
                returnval.add(((AdminGroupDataLocal) iter.next()).getAdminGroup());
            }
        } catch (FinderException e) {
        }

        return returnval;
    } // getAdminGroups


    /**
     * Returns a Collection of AdminGroup the administrator is authorized to.
     * <p/>
     * SuperAdmin is authorized to all groups
     * Other admins are only authorized to the groups containing a subset of authorized CA that the admin
     * himself is authorized to.
     * <p/>
     * The AdminGroup objects only contains only name and caid and no accessdata
     *
     * @param admin The current administrator
     * @param availableCaIds A Collection<Integer> of all CA Ids
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public Collection getAuthorizedAdminGroupNames(Admin admin, Collection availableCaIds) {
        ArrayList returnval = new ArrayList();


        boolean issuperadmin = false;
        try {
            issuperadmin = this.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_SUPERADMINISTRATOR);
        } catch (AuthorizationDeniedException e1) {
        }
        HashSet authorizedcaids = new HashSet();
        HashSet allcaids = new HashSet();
        if (!issuperadmin) {
            authorizedcaids.addAll(getAuthorizer().getAuthorizedCAIds(admin, availableCaIds));
            allcaids.addAll(availableCaIds);
        }

        try {
            Collection result = admingrouphome.findAll();
            Iterator i = result.iterator();

            while (i.hasNext()) {
                AdminGroupDataLocal agdl = (AdminGroupDataLocal) i.next();

                boolean allauthorized = false;
                boolean carecursive = false;
                boolean superadmingroup = false;
                boolean authtogroup = false;

                ArrayList groupcaids = new ArrayList();
                if (!issuperadmin) {
                    // Is admin authorized to all group caid. This is true if admin is authorized to all CAs used by the different admins.
                	Collection admins = agdl.getAdminEntityObjects();
                	Iterator adminsIterator = admins.iterator();
                	boolean onlyAuthorizedCAIds = true;
                	while (adminsIterator.hasNext()) {
                		AdminEntity adminEntity = (AdminEntity) adminsIterator.next();
                		if (!authorizedcaids.contains(adminEntity.getCaId())) {
                			onlyAuthorizedCAIds = false;
                			break;
                		}
                	}
                    if (onlyAuthorizedCAIds) {
                        authtogroup = true;
                        // check access rules
                        Iterator iter = agdl.getAccessRuleObjects().iterator();
                        while (iter.hasNext()) {
                            AccessRule accessrule = ((AccessRule) iter.next());
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
        } catch (FinderException e) {
        }
        return returnval;
    } // getAuthorizedAdminGroupNames

    /**
     * Adds a Collection of AccessRule to an an admin group.
     *
     * @ejb.interface-method view-type="both"
     */
    public void addAccessRules(Admin admin, String admingroupname, Collection accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                (admingrouphome.findByGroupName(admingroupname)).addAccessRules(accessrules);
                signalForAuthorizationTreeUpdate();               
        		String msg = intres.getLocalizedMessage("authorization.accessrulesadded", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.erroraddaccessrules", admingroupname);            	
                error(msg, e);
                getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // addAccessRules


    /**
     * Removes a Collection of (String) containing accessrules to remove from admin group.
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeAccessRules(Admin admin, String admingroupname, Collection accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                (admingrouphome.findByGroupName(admingroupname)).removeAccessRules(accessrules);
                signalForAuthorizationTreeUpdate();
        		String msg = intres.getLocalizedMessage("authorization.accessrulesremoved", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.errorremoveaccessrules", admingroupname);            	
            	error(msg, e);
            	getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // removeAccessRules

    /**
     * Replaces a groups accessrules with a new set of rules
     *
     * @ejb.interface-method view-type="both"
     */
    public void replaceAccessRules(Admin admin, String admingroupname, Collection accessrules) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupDataLocal agdl = admingrouphome.findByGroupName(admingroupname);
                Collection currentrules = agdl.getAdminGroup().getAccessRules();
                ArrayList removerules = new ArrayList();
                Iterator iter = currentrules.iterator();
                while (iter.hasNext()) {
                    removerules.add(((AccessRule) iter.next()).getAccessRule());
                }
                agdl.removeAccessRules(removerules);
                agdl.addAccessRules(accessrules);
                signalForAuthorizationTreeUpdate();
        		String msg = intres.getLocalizedMessage("authorization.accessrulesreplaced", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.errorreplaceaccessrules", admingroupname);            	
            	error(msg, e);
            	getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // replaceAccessRules

    /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values if they already exists.
     *
     * @ejb.interface-method view-type="both"
     */

    public void addAdminEntities(Admin admin, String admingroupname, Collection adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                (admingrouphome.findByGroupName(admingroupname)).addAdminEntities(adminentities);
                signalForAuthorizationTreeUpdate();
        		String msg = intres.getLocalizedMessage("authorization.adminadded", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.erroraddadmin", admingroupname);            	
            	error(msg, e);
            	getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // addAdminEntity


    /**
     * Removes a Collection of AdminEntity from the administrator group.
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeAdminEntities(Admin admin, String admingroupname, Collection adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                (admingrouphome.findByGroupName(admingroupname)).removeAdminEntities(adminentities);
                signalForAuthorizationTreeUpdate();
        		String msg = intres.getLocalizedMessage("authorization.adminremoved", admingroupname);            	
        		getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
        		String msg = intres.getLocalizedMessage("authorization.errorremoveadmin", admingroupname);            	
            	error(msg, e);
            	getLogSession().log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    } // removeAdminEntity

    /**
     * @throws AuthorizationDeniedException if administrator isn't authorized to all issuers of the admin certificates in this group
     *  
     * @ejb.interface-method view-type="both"
     */
    public void isAuthorizedToGroup(Admin administrator, String admingroupname) throws AuthorizationDeniedException {
    	ArrayList al = new ArrayList();	//<int>
    	try {
    		AdminGroupDataLocal adminGroupData = admingrouphome.findByGroupName(admingroupname);
    		Iterator i = adminGroupData.getAdminEntityObjects().iterator();
    		while (i.hasNext()) {
    			int currentCaId = ((AdminEntity) i.next()).getCaId();
    			if (!al.contains(currentCaId)) {
    				isAuthorizedNoLog(administrator, AccessRulesConstants.CAPREFIX + currentCaId);
        			al.add(currentCaId);
    			}
    		}
    	} catch (FinderException e) {
    		error("", e);
    	}
    }

    /**
     * Method used to collect an administrators available access rules based on which rule
     * he himself is authorized to.
     *
     * @param admin is the administrator calling the method.
     * @param availableCaIds A Collection<Integer> of all CA Ids
     * @param enableendentityprofilelimitations Include End Entity Profile access rules
     * @param usehardtokenissuing Include Hard Token access rules
     * @param usekeyrecovery Include Key Recovery access rules
     * @param authorizedEndEntityProfileIds A Collection<Integer> of all auhtorized End Entity Profile ids
     * @param authorizedUserDataSourceIds A Collection<Integer> of all auhtorized user data sources ids
     * @return a Collection of String containing available accessrules.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */

    public Collection getAuthorizedAvailableAccessRules(Admin admin, Collection availableCaIds, boolean enableendentityprofilelimitations,
    		boolean usehardtokenissuing, boolean usekeyrecovery, Collection authorizedEndEntityProfileIds, Collection authorizedUserDataSourceIds) {
        AvailableAccessRules availableAccessRules = new AvailableAccessRules(admin, getAuthorizer(), customaccessrules, availableCaIds, enableendentityprofilelimitations, usehardtokenissuing, usekeyrecovery);
        return availableAccessRules.getAvailableAccessRules(admin,authorizedEndEntityProfileIds, authorizedUserDataSourceIds);
    }

    /**
     * Method used to return an Collection of Integers indicating which CAids a administrator
     * is authorized to access.
     * @param admin The current administrator
     * @param availableCaIds A Collection<Integer> of all CA Ids
     * @return Collection of Integer
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public Collection getAuthorizedCAIds(Admin admin, Collection availableCaIds) {
        return getAuthorizer().getAuthorizedCAIds(admin, availableCaIds);
    }

    /**
     * Method used to return an Collection of Integers indicating which end entity profiles
     * the administrator is authorized to view.
     *
     * @param admin the administrator
     * @param rapriviledge should be one of the end entity profile authorization constans defined in AccessRulesConstants.
     * @param authorizedEndEntityProfileIds A Collection<Integer> of all auhtorized EEP ids
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public Collection getAuthorizedEndEntityProfileIds(Admin admin, String rapriviledge, Collection availableEndEntityProfileId) {
        return getAuthorizer().getAuthorizedEndEntityProfileIds(admin, rapriviledge, availableEndEntityProfileId);
    }

    /**
     * Method to check if an end entity profile exists in any end entity profile rules. Used to avoid desyncronization of profilerules.
     *
     * @param profileid the profile id to search for.
     * @return true if profile exists in any of the accessrules.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public boolean existsEndEntityProfileInRules(Admin admin, int profileid) {
    	trace(">existsEndEntityProfileInRules()");
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
            trace("<existsEndEntityProfileInRules()");
            return count > 0;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // existsEndEntityProfileInRules

    /**
     * Method to check if a ca exists in any ca specific rules. Used to avoid desyncronization of CA rules when ca is removed
     *
     * @param caid the ca id to search for.
     * @return true if ca exists in any of the accessrules.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */

    public boolean existsCAInRules(Admin admin, int caid) {
        return existsCAInAdminGroups(caid) && existsCAInAccessRules(caid);
    } // existsCAInRules
    
    /**
     * Method  to force an update of the autorization rules without any wait.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */

    public void forceRuleUpdate(Admin admin) {
        signalForAuthorizationTreeUpdate();
        updateAuthorizationTree();
    } // existsCAInRules


    /**
     * Help function to existsCAInRules, checks if caid axists among entities in admingroups.
     */
    private boolean existsCAInAdminGroups(int caid) {
    	trace(">existsCAInAdminGroups()");
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
            trace("<existsCAInAdminGroups(): "+exists);
            return exists;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Help function to existsCAInRules, checks if caid axists among accessrules.
     */
    private boolean existsCAInAccessRules(int caid) {
    	trace(">existsCAInAccessRules()");
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
            trace("<existsCAInAccessRules(): "+exists);
            return exists;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // existsCAInAccessRules

    /** Cache this local bean, because it will cause many many database lookups otherwise */
    private AuthorizationTreeUpdateDataLocal atu = null;
    /**
     * Returns a reference to the AuthorizationTreeUpdateDataBean
     */
    private AuthorizationTreeUpdateDataLocal getAuthorizationTreeUpdateData() {
    	if (atu == null) {
            try {
                atu = authorizationtreeupdatehome.findByPrimaryKey(AuthorizationTreeUpdateDataBean.AUTHORIZATIONTREEUPDATEDATA);
            } catch (FinderException e) {
                try {
                    atu = authorizationtreeupdatehome.create();
                } catch (CreateException ce) {
            		String msg = intres.getLocalizedMessage("authorization.errorcreateauthtree");            	
                    error(msg, ce);
                    throw new EJBException(ce);
                }
            }
    	}
        return atu;
    }


    /**
     * Method used check if a reconstruction of authorization tree is needed in the
     * authorization beans.
     *
     * @return true if update is needed.
     */
    private boolean updateNeccessary() {
    	boolean ret = false;
    	// Only do the actual SQL query if we might update the configuration due to cache time anyhow
    	if (this.lastupdatetime < (System.currentTimeMillis() - MIN_TIME_BETWEEN_UPDATES)) {
    		if (log.isDebugEnabled()) {
    			log.debug("Checking if update neccessary");
    		}
            ret = getAuthorizationTreeUpdateData().updateNeccessary(this.authorizationtreeupdate);
            this.lastupdatetime = System.currentTimeMillis(); // we don't want to run the above query often
    	}
    	return ret;
    } // updateNeccessary

    /**
     * method updating authorization tree.
     */
    private void updateAuthorizationTree() {
		if (log.isDebugEnabled()) {
			log.debug("updateAuthorizationTree");
    	}
        getAuthorizer().buildAccessTree(getAdminGroups());
        this.authorizationtreeupdate = getAuthorizationTreeUpdateData().getAuthorizationTreeUpdateNumber();
        this.lastupdatetime = System.currentTimeMillis();
    }

    /**
     * Method incrementing the authorizationtreeupdatenumber and thereby signaling
     * to other beans that they should reconstruct their accesstrees.
     */
    private void signalForAuthorizationTreeUpdate() {
		log.trace(">signalForAuthorizationTreeUpdate");
        getAuthorizationTreeUpdateData().incrementAuthorizationTreeUpdateNumber();
		log.trace("<signalForAuthorizationTreeUpdate");
    }

    private int findFreeAdminGroupId() {
        Random random = new Random();
        int id = random.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                this.admingrouphome.findByPrimaryKey(new Integer(id));
                id = random.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return id;
    } // findFreeCertificateProfileId

} // LocalAuthorizationSessionBean

