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

import java.util.Collection;

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
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * Handles AdminEntity objects.
 * 
 * @version
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AdminEntitySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminEntitySessionBean implements AdminEntitySessionLocal, AdminEntitySessionRemote {

    private static final Logger log = Logger.getLogger(AdminEntitySessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationTreeUpdateDataSessionRemote authorizationTreeUpdateDataSession;
    
    @EJB
    private LogSessionLocal logSession;
    
    /**
     * Adds a Collection of AdminEnity to the admingroup. Changes their values
     * if they already exists.
     */
    public void addAdminEntities(Admin admin, String admingroupname, Collection<AdminEntity> adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }          
                agdl.addAdminEntities(entityManager, adminentities);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
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
     */
    public void removeAdminEntities(Admin admin, String admingroupname, Collection<AdminEntity> adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agdl.removeAdminEntities(entityManager, adminentities);
                authorizationTreeUpdateDataSession.signalForAuthorizationTreeUpdate();
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

}
