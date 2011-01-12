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

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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
public final class CertificateProfileCache {

    private static final Logger LOG = Logger.getLogger(CertificateProfileCache.class);

    /**
     * Cache of profiles, with Id as keys. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Set volatile to make it thread friendly.
     */
    private transient volatile Map<Integer, CertificateProfile> profileCache = null;
    /** Cache of mappings between profileId and profileName */
    private transient volatile Map<Integer, String> idNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private transient volatile Map<String, Integer> nameIdMapCache = null;

    /** help variable used to control that cache update isn't performed to often. */
    private transient volatile long lastupdatetime = -1;  

	public void updateProfileCache(final EntityManager entityManager) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">updateProfileCache");
        }
        final HashMap<Integer, String> idNameCache = new HashMap<Integer, String>();
        final HashMap<String, Integer> nameIdCache = new HashMap<String, Integer>();
        final HashMap<Integer, CertificateProfile> profCache = new HashMap<Integer, CertificateProfile>();

        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ENDUSER), EndUserCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SUBCA), CACertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ROOTCA), RootCACertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_OCSPSIGNER), OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SERVER), ServerCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH), HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC), HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENENC), HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME);
        idNameCache.put(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN), HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME);

        nameIdCache.put(EndUserCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_ENDUSER));
        nameIdCache.put(CACertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_SUBCA));
        nameIdCache.put(RootCACertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_ROOTCA));
        nameIdCache.put(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_OCSPSIGNER));
        nameIdCache.put(ServerCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_SERVER));
        nameIdCache.put(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
        nameIdCache.put(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
        nameIdCache.put(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
        nameIdCache.put(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME, Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));

        try {
            final Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Found " + result.size() + " certificate profiles.");
            }
            final Iterator<CertificateProfileData> i = result.iterator();
            while (i.hasNext()) {
                final CertificateProfileData next = i.next();
                idNameCache.put(next.getId(), next.getCertificateProfileName());
                nameIdCache.put(next.getCertificateProfileName(), next.getId());
                profCache.put(next.getId(), next.getCertificateProfile());
            }
        } catch (Exception e) {
            LOG.error("Error reading certificate profiles: ", e);
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
		boolean ret = false;
        if ((nameIdMapCache == null) || (idNameMapCache == null) || (profileCache == null)
                || (lastupdatetime + EjbcaConfiguration.getCacheCertificateProfileTime() < System.currentTimeMillis())) {
            ret = true;
        }
        return ret;
	}

	public Map<Integer, CertificateProfile> getProfileCache() {
		return profileCache;
	}

	public Map<Integer, String> getIdNameMapCache() {
		return idNameMapCache;
	}

	public Map<String, Integer> getNameIdMapCache() {
		return nameIdMapCache;
	}
	
}
