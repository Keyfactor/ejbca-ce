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
package org.cesecore.core.ejb.ra.raadmin;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Class Holding cache variable. Needed because EJB spec does not allow volatile, non-final fields
 * in session beans.
 * 
 * This cache is designed for continuous background updates and will respond with the latest
 * object in the cache. This means that you will not get a performance hit when when the
 * cache is out of date, but you might get a object that is slightly older than the cache timeout.
 * 
 * @version $Id$
 */
public final class EndEntityProfileCache {

    private static final Logger LOG = Logger.getLogger(EndEntityProfileCache.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    /*
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */

    /** Cache of mappings between profileId and profileName */
    private volatile HashMap<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private volatile Map<String, Integer> nameIdMapCache = null;
    /** Cache of end entity profiles, with Id as keys */
    private volatile Map<Integer, EndEntityProfile> profileCache = null;

    private static final ReentrantLock fairLock = new ReentrantLock(true);

    public void updateProfileCache(final EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache");
        }
        final HashMap<Integer, String> idNameCache = new HashMap<Integer, String>();
        final HashMap<String, Integer> nameIdCache = new HashMap<String, Integer>();
        final HashMap<Integer, EndEntityProfile> profCache = new HashMap<Integer, EndEntityProfile>();
        idNameCache.put(Integer.valueOf(SecConst.EMPTY_ENDENTITYPROFILE), EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME);
        nameIdCache.put(EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME, Integer.valueOf(SecConst.EMPTY_ENDENTITYPROFILE));
        try {
        	fairLock.lock();	// Queue up update requests and run them sequentially (better then when older db reads overwrite our cache..)
        	try {
        		final List<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        		for (final EndEntityProfileData next : result) {
        			final Integer id = Integer.valueOf(next.getId());
        			final String profileName = next.getProfileName();
        			idNameCache.put(id, profileName);
        			nameIdCache.put(profileName, id);
        			profCache.put(id, next.getProfile());
        		}
        	} catch (Exception e) {
        		LOG.error(INTRES.getLocalizedMessage("ra.errorreadprofiles"), e);
        	}
        	idNameMapCache = idNameCache;
        	nameIdMapCache = nameIdCache;
        	profileCache = profCache;
        } finally {
        	fairLock.unlock();
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<updateProfileCache");
        }
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public Map<Integer, EndEntityProfile> getProfileCache(final EntityManager entityManager) {
		if (EjbcaConfiguration.getCacheEndEntityProfileTime() == 0) {
			// Always update if no caching is used
			updateProfileCache(entityManager);
		}
		return profileCache;
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public HashMap<Integer, String> getIdNameMapCache(final EntityManager entityManager) {
		if (EjbcaConfiguration.getCacheEndEntityProfileTime() == 0) {
			// Always update if no caching is used
			updateProfileCache(entityManager);
		}
		return idNameMapCache;
	}

	/** @return the latest object from the cache or a current database representation if no caching is used. */
	public Map<String, Integer> getNameIdMapCache(final EntityManager entityManager) {
		if (EjbcaConfiguration.getCacheEndEntityProfileTime() == 0) {
			// Always update if no caching is used
			updateProfileCache(entityManager);
		}
		return nameIdMapCache;
	}
}
