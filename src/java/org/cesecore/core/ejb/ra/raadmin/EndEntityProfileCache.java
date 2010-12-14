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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.persistence.EntityManager;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Class Holding cache variable. Needed because EJB spec does not allow volatile, non-final 
 * fields in session beans.
 * This is a trivial cache, too trivial, it needs manual handling of setting the cache variable, this class does not keep track on if
 * the cache variable is null or not, or when the cache must be updated. The using class must ensure that it does not try to use a null value 
 * (by calling updateProfileCache before any cache is used), and that the cache is updated when 
 * the method "needsUpdate" returns true. caller must make sure updateProfileCache is called at least once.
 * 
 * An example of this is by using internal methods in the calling class like:
 * <pre>
 *  private Map<Integer, CertificateProfile> getProfileCacheInternal() {
 *   	if (profileCache.needsUpdate()) {
 *   		updateProfileCache(entityManager);
 *   	}
 *       return profileCache.getProfileCache();
 *   }
 * </pre>
 * @version $Id$
 */
public final class EndEntityProfileCache {

    private static final Logger LOG = Logger.getLogger(EndEntityProfileCache.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();


    /**
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    /**  */
    /** Cache of mappings between profileId and profileName */
    private volatile HashMap<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private volatile Map<String, Integer> nameIdMapCache = null;
    /** Cache of end entity profiles, with Id as keys */
    private volatile Map<Integer, EndEntityProfile> profileCache = null;

    /** help variable used to control that cache update isn't performed to often. */
    private volatile long lastupdatetime = -1;  

	public EndEntityProfileCache() {
		// Do nothing
	}

	public void updateProfileCache(EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache");
        }
        final HashMap<Integer, String> idNameCache = new HashMap<Integer, String>();
        final HashMap<String, Integer> nameIdCache = new HashMap<String, Integer>();
        final HashMap<Integer, EndEntityProfile> profCache = new HashMap<Integer, EndEntityProfile>();
        idNameCache.put(Integer.valueOf(SecConst.EMPTY_ENDENTITYPROFILE), EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME);
        nameIdCache.put(EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME, Integer.valueOf(SecConst.EMPTY_ENDENTITYPROFILE));
        try {
            final Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found " + result.size() + " end entity profiles.");
            }
            final Iterator<EndEntityProfileData> i = result.iterator();
            while (i.hasNext()) {
                final EndEntityProfileData next = i.next();
                // debug("Added "+next.getId()+ ", "+next.getProfileName());
                idNameCache.put(next.getId(), next.getProfileName());
                nameIdCache.put(next.getProfileName(), next.getId());
                profCache.put(next.getId(), next.getProfile());
            }
        } catch (Exception e) {
            final String msg = INTRES.getLocalizedMessage("ra.errorreadprofiles");
            LOG.error(msg, e);
        }
        idNameMapCache = idNameCache;
        nameIdMapCache = nameIdCache;
        profileCache = profCache;
        lastupdatetime = System.currentTimeMillis();
        if (LOG.isTraceEnabled()) {
            LOG.trace("<updateProfileCache");
        }
	}

	public boolean needsUpdate() {
        if ((nameIdMapCache == null) || (idNameMapCache == null) || (profileCache == null)
                || (lastupdatetime + EjbcaConfiguration.getCacheEndEntityProfileTime() < System.currentTimeMillis())) {
            return true;
        }
        return false;
	}

	public Map<Integer, EndEntityProfile> getProfileCache() {
		return profileCache;
	}

	public HashMap<Integer, String> getIdNameMapCache() {
		return idNameMapCache;
	}

	public Map<String, Integer> getNameIdMapCache() {
		return nameIdMapCache;
	}
	
}
