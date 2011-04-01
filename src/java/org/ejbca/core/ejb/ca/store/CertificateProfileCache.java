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
package org.ejbca.core.ejb.ca.store;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ca.caadmin.CertificateProfileData;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.certificateprofiles.CACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenSignCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.OCSPSignerCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.RootCACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.ServerCertificateProfile;

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
public final class CertificateProfileCache {

    private static final Logger LOG = Logger.getLogger(CertificateProfileCache.class);

    /*
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */

    /** Cache of mappings between profileId and profileName */
    private transient volatile Map<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private transient volatile Map<String, Integer> nameIdMapCache = null;
    /** Cache of certificate profiles, with Id as keys */
    private transient volatile Map<Integer, CertificateProfile> profileCache = null;

    private volatile long lastUpdate = 0;

    /* Create template maps with all static constants */
    private static final HashMap<Integer, String> idNameMapCacheTemplate = new HashMap<Integer, String>();
    private static final HashMap<String, Integer> nameIdMapCacheTemplate = new HashMap<String, Integer>();
    static {
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ENDUSER), EndUserCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SUBCA), CACertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ROOTCA), RootCACertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_OCSPSIGNER), OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SERVER), ServerCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH), HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC), HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENENC), HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME);
    	idNameMapCacheTemplate.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN), HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME);
    	nameIdMapCacheTemplate.put(EndUserCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_ENDUSER));
    	nameIdMapCacheTemplate.put(CACertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_SUBCA));
    	nameIdMapCacheTemplate.put(RootCACertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_ROOTCA));
    	nameIdMapCacheTemplate.put(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_OCSPSIGNER));
    	nameIdMapCacheTemplate.put(ServerCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_SERVER));
    	nameIdMapCacheTemplate.put(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
    	nameIdMapCacheTemplate.put(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
    	nameIdMapCacheTemplate.put(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
    	nameIdMapCacheTemplate.put(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
    }
    
    private static final ReentrantLock lock = new ReentrantLock(false);

    /**
     * Fetch all profiles from the database, unless cache is enabled, valid and we do not force an update.
     * @param entityManager is required for reading the profiles from the database if we need to update the cache
     * @param force if true, this will force an update even if the cache is not yet invalid
     */
	public void updateProfileCache(final EntityManager entityManager, final boolean force) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache");
        }
        final long cacheCertificateProfileTime = EjbcaConfiguration.getCacheCertificateProfileTime();
        final long now = System.currentTimeMillis();
        try {
        	lock.lock();
        	if (!force && cacheCertificateProfileTime!=0 && lastUpdate+cacheCertificateProfileTime > now) {
        		return;	// We don't need to update cache
        	}
        	lastUpdate = now;
        } finally {
        	lock.unlock();
        }
        @SuppressWarnings("unchecked")
        final Map<Integer, String> idNameCache = (Map<Integer, String>) idNameMapCacheTemplate.clone();
        @SuppressWarnings("unchecked")
        final Map<String, Integer> nameIdCache = (Map<String, Integer>) nameIdMapCacheTemplate.clone();
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
