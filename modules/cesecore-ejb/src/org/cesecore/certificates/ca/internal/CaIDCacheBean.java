/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Class Holding cache variable.
 * 
 * This cache is designed so only one thread at the time will update the cache if it is too old. Other
 * threads will happily return a bit too old object. If a cache update is forced, for example when
 * a profile is edited, it will always update the cache even if the commit of the transaction fails.
 * 
 * Another known issue during forced updates is the race condition exists, so an update in progress
 * might overwrite the result from forced update's database query.
 * 
 * The intention of this design is better throughput than fully ordered sequential updates.
 * 
 * @version $Id$
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class CaIDCacheBean {

    private final Logger LOG = Logger.getLogger(CaIDCacheBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    /*
     * Cache of CA IDs. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */

    /** Cache of CA IDs */
    private volatile List<Integer> idCache = null;

    private volatile long lastUpdate = 0;

    private ReentrantLock lock;
    
    @PostConstruct
    public void initialize() {
        idCache = new ArrayList<Integer>();
        lock = new ReentrantLock(false);

        try {
            updateCache(true);
        } catch (RuntimeException e) {
            //We don't want to murder the entire deployment if the database happens to be unresponsive during startup, it's something we might 
            //recover from
            LOG.error(e);
        }
    }

    /**
     * This method sets the update time back down to zero, effectively forcing the cache to be reloaded on next read. Required due to the fact that 
     * the cache can't reload until whatever transaction performing CRUD ops finishes.
     */
    public void forceCacheExpiration() {
        LOG.debug("Flushing CA ID cache by forceCacheExpiration");
        lastUpdate = 0;
    }
    
    /**
     * Fetch all CA IDs from the database, unless cache is enabled, valid and we do not force an update.
     * 
     * @param force if true, this will force an update even if the cache is not yet invalid
     */
    private void updateCache(final boolean force) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateCache");
        }
        final long cacheTime = CesecoreConfiguration.getCacheCaTimeInCaSession();
        final long now = System.currentTimeMillis();
        // Check before acquiring lock. Update cache if we force cache update or cache is disabled in config (cacheTime = 0) or cache expired
        if (!force && cacheTime != 0 && lastUpdate + cacheTime > now) {
            return; // We don't need to update cache
        }
        try {
            lock.lock();
            if (!force && cacheTime != 0 && lastUpdate + cacheTime > now) {
                return; // We don't need to update cache
            }
            lastUpdate = now; // make sure next thread does not also pass the update test
        } finally {
            lock.unlock();
        }
        if (LOG.isDebugEnabled()) {
        	LOG.debug("Loading CA ID cache from database");
        }
        final List<Integer> idCacheTemp = findAllCaIds();
        idCache = idCacheTemp;
        if (LOG.isTraceEnabled()) {
            LOG.trace("<updateCache");
        }
    }

    /** @return return the query results as a List<Integer>. */
    @SuppressWarnings("unchecked")
    private List<Integer> findAllCaIds() {
        final Query query = entityManager.createQuery("SELECT a.caId FROM CAData a");
        return query.getResultList();
    }
    

    /** @return the latest List from the cache, which will be refreshed if needed. */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Integer> getCacheContent() {
        updateCache(false);
        return idCache;
    }

}
