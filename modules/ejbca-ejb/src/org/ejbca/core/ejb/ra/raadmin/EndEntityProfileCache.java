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
package org.ejbca.core.ejb.ra.raadmin;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.LogRedactionConfiguration;
import org.cesecore.configuration.LogRedactionConfigurationCache;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Class Holding cache variable. Needed because EJB spec does not allow volatile, non-final fields
 * in session beans.
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
public enum EndEntityProfileCache {
    INSTANCE;

    private final Logger LOG = Logger.getLogger(EndEntityProfileCache.class);
    /** Internal localization of logs and errors */
    private final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    /*
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */

    /** Cache of mappings between profileId and profileName */
    private volatile Map<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private volatile Map<String, Integer> nameIdMapCache = null;
    /** Cache of end entity profiles, with Id as keys */
    private volatile Map<Integer, EndEntityProfile> profileCache = null;
    
    private volatile long lastUpdate = 0;

    /* Create template maps with all static constants */
    private final HashMap<Integer,String> idNameMapCacheTemplate = new HashMap<Integer,String>();
    private final HashMap<String,Integer> nameIdMapCacheTemplate = new HashMap<String,Integer>();

    private final ReentrantLock lock = new ReentrantLock(false);
    
    private EndEntityProfileCache() {
    	idNameMapCacheTemplate.put(Integer.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE), EndEntityConstants.EMPTY_ENDENTITYPROFILENAME);
    	nameIdMapCacheTemplate.put(EndEntityConstants.EMPTY_ENDENTITYPROFILENAME, Integer.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE));
    }

    /**
     * Fetch all profiles from the database, unless cache is enabled, valid and we do not force an update.
     * @param entityManager is required for reading the profiles from the database if we need to update the cache
     * @param force if true, this will force an update even if the cache is not yet invalid
     */
    public void updateProfileCache(final EntityManager entityManager, final boolean force) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache: "+force);
        }
        final long cacheEndEntityProfileTime = EjbcaConfiguration.getCacheEndEntityProfileTime();
        final long now = System.currentTimeMillis();
        // Check before acquiring lock
        if (!force && cacheEndEntityProfileTime!=0 && lastUpdate+cacheEndEntityProfileTime > now) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("<updateProfileCache returning, cache time not expired: "+cacheEndEntityProfileTime);
            }
            return; // We don't need to update cache
        }
        try {
        	lock.lock();
        	if (!force && cacheEndEntityProfileTime!=0 && lastUpdate+cacheEndEntityProfileTime > now) {
        		return;	// We don't need to update cache
        	}
        	lastUpdate = now; // make sure next thread does not also pass the update test
        } finally {
        	lock.unlock();
        }
        final Map<Integer, String> idNameCache = new HashMap<Integer, String>(idNameMapCacheTemplate);
        final Map<String, Integer> nameIdCache = new HashMap<String, Integer>(nameIdMapCacheTemplate);
        final Map<Integer, EndEntityProfile> profCache = new HashMap<Integer, EndEntityProfile>();
        
        final Map<Integer, LogRedactionConfiguration> idToLogRedactionConfigCache = new HashMap<>();
        final Map<String, LogRedactionConfiguration> nameToLogRedactionConfigCache = new HashMap<>();
        
        try {
        	final List<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        	for (final EndEntityProfileData next : result) {
        		final Integer id = Integer.valueOf(next.getId());
        		final String profileName = next.getProfileName();
        		idNameCache.put(id, profileName);
        		nameIdCache.put(profileName, id);
        		
        		EndEntityProfile profile = next.getProfile();
        		profCache.put(id, profile);
        		
        		LogRedactionConfiguration logRedactionConfig = new LogRedactionConfiguration(profile.isRedactPii());
        		idToLogRedactionConfigCache.put(id, logRedactionConfig);
        		nameToLogRedactionConfigCache.put(profileName, logRedactionConfig);
        		
        	}
        } catch (Exception e) {
        	LOG.error(INTRES.getLocalizedMessage("ra.errorreadprofiles"), e);
        }
        idNameMapCache = idNameCache;
        nameIdMapCache = nameIdCache;
        profileCache = profCache;
        
        LogRedactionConfigurationCache.INSTANCE.updateLogRedactionCache(idToLogRedactionConfigCache, nameToLogRedactionConfigCache);
        
        if (LOG.isTraceEnabled()) {
            final long end = System.currentTimeMillis();
            LOG.trace("<updateProfileCache took: "+(end-now)+"ms");
        }
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public Map<Integer, EndEntityProfile> getProfileCache(final EntityManager entityManager) {
		updateProfileCache(entityManager, false);
		return profileCache;
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public Map<Integer, String> getIdNameMapCache(final EntityManager entityManager) {
		updateProfileCache(entityManager, false);
		return idNameMapCache;
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public Map<String, Integer> getNameIdMapCache(final EntityManager entityManager) {
		updateProfileCache(entityManager, false);
		return nameIdMapCache;
	}
}
