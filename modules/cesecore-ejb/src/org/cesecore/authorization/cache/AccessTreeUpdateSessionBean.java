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

import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authorization.access.AuthorizationCacheReload;
import org.cesecore.authorization.access.AuthorizationCacheReloadListener;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;

/**
 * Bean to handle the AuthorizationTreeUpdateData entity.
 * 
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessTreeUpdateSessionLocal")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AccessTreeUpdateSessionBean implements AccessTreeUpdateSessionLocal {

    private static final Logger LOG = Logger.getLogger(AccessTreeUpdateSessionBean.class);

    // JBoss 7.1.1 has a problem with JEE Events (see Johans comment in ECA-4919, probably caused by https://bz.apache.org/bugzilla/show_bug.cgi?id=50789)
    // The problem is that you get an exception when a META-INF/breans.xml file is present.
    // So for now we just use the standard java Runnable interface (which can only be set within the same JVM)
    private final Collection<AuthorizationCacheReloadListener> authCacheReloadEvent = new ArrayList<>();
    // Once this problem is solved, we can do:
    /*@Inject
    private Event<AuthorizationCacheReload> authCacheReloadEvent;*/
    
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
            } catch (Exception e) {
                LOG.error(InternalResources.getInstance().getLocalizedMessage("authorization.errorcreateauthtree"), e);
                throw new EJBException(e);
            }
        } else {
            accessTreeUpdateData.setAccessTreeUpdateNumber(accessTreeUpdateData.getAccessTreeUpdateNumber() + 1);
        }
        LOG.debug("Invoking event");
        final AuthorizationCacheReload event = new AuthorizationCacheReload(accessTreeUpdateData.getAccessTreeUpdateNumber());
        // When the problem with JEE Events is solved, we can do this:
        //authCacheReloadEvent.fire(event);
        for (AuthorizationCacheReloadListener observer : authCacheReloadEvent) {
            observer.onReload(event);
        }
        LOG.debug("Done invoking event");
    }
    
    // When the problem with JEE Events is solved, we can remove this method
    @Override
    public void addReloadEvent(final AuthorizationCacheReloadListener observer) {
        authCacheReloadEvent.add(observer);
    }
}
