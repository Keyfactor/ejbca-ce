/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authorization.cache;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Bean to handle the AccessTreeUpdateData entity.
 * 
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessTreeUpdateSessionBean implements AccessTreeUpdateSessionLocal {

    private static final Logger LOG = Logger.getLogger(AccessTreeUpdateSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)    // We don't modify the database in this call
    public int getAccessTreeUpdateNumber() {
        final AccessTreeUpdateData accessTreeUpdateData = entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
        if (accessTreeUpdateData==null) {
            // No update has yet been persisted, so we return the default value
            return AccessTreeUpdateData.DEFAULTACCESSTREEUPDATENUMBER;
        }
        return accessTreeUpdateData.getAccessTreeUpdateNumber();
    }

    @Override
    public void signalForAccessTreeUpdate() {
        AccessTreeUpdateData accessTreeUpdateData = entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
        if (accessTreeUpdateData==null) {
            // We need to create the database row and incremented the value directly since this is an call to update it
            accessTreeUpdateData = new AccessTreeUpdateData();
            accessTreeUpdateData.setAccessTreeUpdateNumber(AccessTreeUpdateData.DEFAULTACCESSTREEUPDATENUMBER + 1);
            entityManager.persist(accessTreeUpdateData);

        } else {
            accessTreeUpdateData.setAccessTreeUpdateNumber(accessTreeUpdateData.getAccessTreeUpdateNumber() + 1);
        }
        LOG.debug("Invoking event");
        final AuthorizationCacheReload event = new AuthorizationCacheReload(accessTreeUpdateData.getAccessTreeUpdateNumber());
        AuthorizationCacheReloadListeners.INSTANCE.onReload(event);
        LOG.debug("Done invoking event");
    }
    
    @Override
    public void addReloadEvent(final AuthorizationCacheReloadListener observer) {
        AuthorizationCacheReloadListeners.INSTANCE.addListener(observer);
    }
}
