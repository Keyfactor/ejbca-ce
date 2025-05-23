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

import jakarta.ejb.EJBException;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;

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
            try {
                accessTreeUpdateData = new AccessTreeUpdateData();
                accessTreeUpdateData.setAccessTreeUpdateNumber(AccessTreeUpdateData.DEFAULTACCESSTREEUPDATENUMBER+1);
                entityManager.persist(accessTreeUpdateData);
                // Additionally we set the marker that this (new) installation should use the new union access rule pattern
                setNewAuthorizationPatternMarker();
            } catch (Exception e) {
                LOG.error(InternalResources.getInstance().getLocalizedMessage("authorization.errorcreateauthtree"), e);
                throw new EJBException(e);
            }
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

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean isNewAuthorizationPatternMarkerPresent() {
        return entityManager.find(AccessTreeUpdateData.class, AccessTreeUpdateData.NEW_AUTHORIZATION_PATTERN_MARKER)!=null;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void setNewAuthorizationPatternMarker() {
        /*
         * Use a row in this table as a marker, since it is already a dependency from AuthorizationSessionBean.
         * (Otherwise we would have to depend on reading configuration which in turn depends back on authorization.)
         */
        if (!isNewAuthorizationPatternMarkerPresent()) {
            final AccessTreeUpdateData marker = new AccessTreeUpdateData();
            marker.setPrimaryKey(AccessTreeUpdateData.NEW_AUTHORIZATION_PATTERN_MARKER);
            entityManager.persist(marker);
        }
    }
}
