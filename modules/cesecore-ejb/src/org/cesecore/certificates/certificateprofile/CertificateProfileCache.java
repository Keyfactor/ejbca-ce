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
package org.cesecore.certificates.certificateprofile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

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
 * Probably based on EJBCA's org.ejbca.core.ejb.ca.store.CertificateProfileCache r11155
 * 
 * @version $Id$
 */
public enum CertificateProfileCache {
    INSTANCE;

    private final Logger LOG = Logger.getLogger(CertificateProfileCache.class);

    /*
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */

    /** Cache of mappings between profileId and profileName */
    private volatile Map<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private volatile Map<String, Integer> nameIdMapCache = null;
    /** Cache of certificate profiles, with Id as keys */
    private volatile Map<Integer, CertificateProfile> profileCache = null;

    private volatile long lastUpdate = 0;

    /* Create template maps with all static constants */
    private final HashMap<Integer, String> idNameMapCacheTemplate = new HashMap<Integer, String>();
    private final HashMap<String, Integer> nameIdMapCacheTemplate = new HashMap<String, Integer>();

    private final ReentrantLock lock = new ReentrantLock(false);

    private CertificateProfileCache() {
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER), CertificateProfile.ENDUSERPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA), CertificateProfile.SUBCAPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA), CertificateProfile.ROOTCAPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER), CertificateProfile.OCSPSIGNERPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER), CertificateProfile.SERVERPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH), CertificateProfile.HARDTOKENAUTHPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC), CertificateProfile.HARDTOKENAUTHENCPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC), CertificateProfile.HARDTOKENENCPROFILENAME);
        idNameMapCacheTemplate.put(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN), CertificateProfile.HARDTOKENSIGNPROFILENAME);
        nameIdMapCacheTemplate.put(CertificateProfile.ENDUSERPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
        nameIdMapCacheTemplate.put(CertificateProfile.SUBCAPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA));
        nameIdMapCacheTemplate.put(CertificateProfile.ROOTCAPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA));
        nameIdMapCacheTemplate.put(CertificateProfile.OCSPSIGNERPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER));
        nameIdMapCacheTemplate.put(CertificateProfile.SERVERPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER));
        nameIdMapCacheTemplate.put(CertificateProfile.HARDTOKENAUTHPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH));
        nameIdMapCacheTemplate.put(CertificateProfile.HARDTOKENAUTHENCPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
        nameIdMapCacheTemplate.put(CertificateProfile.HARDTOKENENCPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC));
        nameIdMapCacheTemplate.put(CertificateProfile.HARDTOKENSIGNPROFILENAME, Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
    }

    /**
     * Fetch all profiles from the database, unless cache is enabled, valid and we do not force an update.
     * 
     * @param entityManager is required for reading the profiles from the database if we need to update the cache
     * @param force if true, this will force an update even if the cache is not yet invalid
     */
    public void updateProfileCache(final EntityManager entityManager, final boolean force) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache");
        }
        final long cacheCertificateProfileTime = CesecoreConfiguration.getCacheCertificateProfileTime();
        final long now = System.currentTimeMillis();
        // Check before acquiring lock
        if (!force && cacheCertificateProfileTime != 0 && lastUpdate + cacheCertificateProfileTime > now) {
            return; // We don't need to update cache
        }
        try {
            lock.lock();
            if (!force && cacheCertificateProfileTime != 0 && lastUpdate + cacheCertificateProfileTime > now) {
                return; // We don't need to update cache
            }
            lastUpdate = now; // make sure next thread does not also pass the update test
        } finally {
            lock.unlock();
        }
        final Map<Integer, String> idNameCache = new HashMap<Integer, String>(idNameMapCacheTemplate);
        final Map<String, Integer> nameIdCache = new HashMap<String, Integer>(nameIdMapCacheTemplate);
        final Map<Integer, CertificateProfile> profCache = new HashMap<Integer, CertificateProfile>();
        try {
            final List<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
            for (final CertificateProfileData current : result) {
                final Integer id = Integer.valueOf(current.getId());
                final String certificateProfileName = current.getCertificateProfileName();
                idNameCache.put(id, certificateProfileName);
                nameIdCache.put(certificateProfileName, id);
                profCache.put(id, current.getCertificateProfile());
            }
        } catch (Exception e) {
            LOG.error("Error reading certificate profiles: ", e);
        }
        idNameMapCache = idNameCache;
        nameIdMapCache = nameIdCache;
        profileCache = profCache;
        if (LOG.isTraceEnabled()) {
            LOG.trace("<updateProfileCache");
        }
    }

    /** @return the latest object from the cache or a current database representation if no caching is used. */
    public Map<Integer, CertificateProfile> getProfileCache(final EntityManager entityManager) {
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
