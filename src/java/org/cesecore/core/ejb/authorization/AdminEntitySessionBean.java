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
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AdminGroupData;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * Handles AdminEntity objects.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AdminEntitySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminEntitySessionBean implements AdminEntitySessionLocal, AdminEntitySessionRemote {

    private static final Logger LOG = Logger.getLogger(AdminEntitySessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationTreeUpdateDataSessionLocal authTreeSession;
    
    @EJB
    private LogSessionLocal logSession;
    
    @Override
    public void addAdminEntities(final Admin admin, final String admingroupname, final Collection<AdminEntity> adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                final AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    String msg = INTRES.getLocalizedMessage("authorization.erroraddadmin", admingroupname);
                    msg += ". Admin group does not exist.";
                    LOG.info(msg);
                }          
                agdl.addAdminEntities(entityManager, adminentities);
                authTreeSession.signalForAuthorizationTreeUpdate();
                final String msg = INTRES.getLocalizedMessage("authorization.adminadded", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.erroraddadmin", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }

    @Override
    public void removeAdminEntities(final Admin admin, final String admingroupname, final Collection<AdminEntity> adminentities) {
        if (!admingroupname.equals(AdminGroup.DEFAULTGROUPNAME)) {
            try {
                final AdminGroupData agdl = AdminGroupData.findByGroupName(entityManager, admingroupname);
                if (agdl == null) {
                    throw new FinderException("Could not find admin group " + admingroupname);
                }
                agdl.removeAdminEntities(entityManager, adminentities);
                authTreeSession.signalForAuthorizationTreeUpdate();
                final String msg = INTRES.getLocalizedMessage("authorization.adminremoved", admingroupname);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES, msg);
            } catch (Exception e) {
                final String msg = INTRES.getLocalizedMessage("authorization.errorremoveadmin", admingroupname);
                LOG.error(msg, e);
                logSession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES, msg);
            }
        }
    }
}
