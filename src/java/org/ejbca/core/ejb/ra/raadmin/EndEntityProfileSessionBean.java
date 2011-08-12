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
package org.ejbca.core.ejb.ra.raadmin;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

/**
 * Session bean for handling EndEntityProfiles
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityProfileSessionBean implements EndEntityProfileSessionLocal, EndEntityProfileSessionRemote {

    private static final Logger LOG = Logger.getLogger(EndEntityProfileSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    private static final Random RANDOM = new Random(new Date().getTime());

    /** Cache of end entity profiles and id-name mappings */
    private static final EndEntityProfileCache profileCache = new EndEntityProfileCache();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal authSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    @Override
    public void addEndEntityProfile(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile) throws EndEntityProfileExistsException {
        addEndEntityProfile(admin, findFreeEndEntityProfileId(), profilename, profile);
    }

    @Override
    public void addEndEntityProfile(final AuthenticationToken admin, final int profileid, final String profilename, final EndEntityProfile profile) throws EndEntityProfileExistsException {
        if (profilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
            final String msg = INTRES.getLocalizedMessage("ra.erroraddprofilefixed", profilename, EMPTY_ENDENTITYPROFILENAME);
            LOG.info(msg);
            throw new EndEntityProfileExistsException(msg);
        } else if (!isFreeEndEntityProfileId(profileid)) {
        	final String msg = INTRES.getLocalizedMessage("ra.erroraddprofileexists", profilename);
            LOG.info(msg);
            throw new EndEntityProfileExistsException(msg);
        } else if (EndEntityProfileData.findByProfileName(entityManager, profilename) != null) {
        	final String msg = INTRES.getLocalizedMessage("ra.erroraddprofileexists", profilename);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException(msg);
        } else {
            try {
                entityManager.persist(new EndEntityProfileData(Integer.valueOf(profileid), profilename, profile));
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("ra.addedprofile", profilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), profilename, String.valueOf(profileid), details);
            } catch (Exception e) {
            	final String msg = INTRES.getLocalizedMessage("ra.erroraddprofile", profilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), profilename, String.valueOf(profileid), details);
            }
        }
    }

    @Override
    public void changeEndEntityProfile(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile) {
        internalChangeEndEntityProfileNoFlushCache(admin, profilename, profile);
        flushProfileCache();
    }

    @Override
    public void cloneEndEntityProfile(final AuthenticationToken admin, final String orgname, final String newname) throws EndEntityProfileExistsException {
        if (newname.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
        	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
        if (EndEntityProfileData.findByProfileName(entityManager, newname) == null) {
        	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, orgname);
            boolean success = false;
            if (pdl != null) {
            	try {
            		int profileid = findFreeEndEntityProfileId();
            		entityManager.persist(new EndEntityProfileData(Integer.valueOf(profileid), newname, (EndEntityProfile) pdl.getProfile().clone()));
            		flushProfileCache();
            		final String msg = INTRES.getLocalizedMessage("ra.clonedprofile", newname, orgname);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), newname, String.valueOf(profileid), details);
            		success = true;
            	} catch (CloneNotSupportedException e) {
            		LOG.error("Cloe not supported?: ", e);
            	}
            }
            if (!success) {
            	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), newname, null, details);
            }
        } else {
        	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCertificateProfileInEndEntityProfiles(final AuthenticationToken admin, final int profileid) {
        String[] availprofiles = null;
        boolean exists = false;
        final Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        final Iterator<EndEntityProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
            availprofiles = i.next().getProfile().getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
            for (int j = 0; j < availprofiles.length; j++) {
                if (Integer.parseInt(availprofiles[j]) == profileid) {
                    exists = true;
                    break;
                }
            }
        }
        return exists;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCAInEndEntityProfiles(final AuthenticationToken admin, final int caid) {
        String[] availablecas = null;
        boolean exists = false;
        final Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        final Iterator<EndEntityProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
        	final EndEntityProfileData ep = i.next();
            availablecas = ep.getProfile().getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
            for (int j = 0; j < availablecas.length; j++) {
                if (Integer.parseInt(availablecas[j]) == caid) {
                    exists = true;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("CA exists in entity profile " + ep.getProfileName());
                    }
                    break;
                }
            }
        }
        return exists;
    }

    @Override
    public int findFreeEndEntityProfileId() {
    	int id = Math.abs(RANDOM.nextInt(Integer.MAX_VALUE));
    	// Never generate id's less than 10000
        while ((id < 10000) || (EndEntityProfileData.findById(entityManager, id) != null)) {
            id = Math.abs(RANDOM.nextInt(Integer.MAX_VALUE));
        }
        return id;
    }

    @Override
    public void flushProfileCache() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flushProfileCache");
        }
        profileCache.updateProfileCache(entityManager, true);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Flushed profile cache");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityProfile getEndEntityProfile(final AuthenticationToken admin, final String profilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfile(" + profilename + ")");
        }
        EndEntityProfile returnval = null;
        if (profilename.equals(EMPTY_ENDENTITYPROFILENAME)) {
            returnval = new EndEntityProfile(true);
        } else {
        	final Integer id = profileCache.getNameIdMapCache(entityManager).get(profilename);
        	if (id != null) {
        		returnval = getEndEntityProfile(admin, id);
        	}
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfile(" + profilename + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAuthorizedEndEntityProfileIds(final AuthenticationToken admin) {
    	final ArrayList<Integer> returnval = new ArrayList<Integer>();
    	final HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAvailableCAs(admin));
		// If this is the special value ALLCAs we are authorized
    	authorizedcaids.add(Integer.valueOf(SecConst.ALLCAS));
        if (authSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            returnval.add(SecConst.EMPTY_ENDENTITYPROFILE);
        }
        try {
        	for (final Entry<Integer, EndEntityProfile> entry : profileCache.getProfileCache(entityManager).entrySet()) {
        		// Check if all profiles available CAs exists in authorizedcaids.
        		final String availableCasString = entry.getValue().getValue(EndEntityProfile.AVAILCAS, 0);
        		if (availableCasString != null) {
        			boolean authorizedToProfile = true;
        			for (final String caidString : availableCasString.split(EndEntityProfile.SPLITCHAR)) {
        				if (!authorizedcaids.contains(Integer.parseInt(caidString))) {
        					authorizedToProfile = false;
        					if (LOG.isDebugEnabled()) {
        						LOG.debug("Profile " + entry.getKey().toString() + " not authorized");
        					}
        					break;
        				}
        			}
        			if (authorizedToProfile) {
        				returnval.add(entry.getKey());
        			}
        		}
        	}
        } catch (Exception e) {
            LOG.error(INTRES.getLocalizedMessage("ra.errorgetids"), e);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityProfile getEndEntityProfile(final AuthenticationToken admin, final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfile(" + id + ")");
        }
        EndEntityProfile returnval = null;
        if (id == SecConst.EMPTY_ENDENTITYPROFILE) {
            returnval = new EndEntityProfile(true);
        } else {
    		// We need to clone the profile, otherwise the cache contents will be modifyable from the outside
        	final EndEntityProfile eep = profileCache.getProfileCache(entityManager).get(Integer.valueOf(id));
    		try {
    			if (eep != null) {
    				returnval = (EndEntityProfile)eep.clone();
    			}
    		} catch (CloneNotSupportedException e) {
    			LOG.error("Should never happen: ", e);
    			throw new RuntimeException(e);
    		}
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfile(id): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getEndEntityProfileId(final AuthenticationToken admin, final String profilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfileId(" + profilename + ")");
        }
        int returnval = 0;
        final Integer id = profileCache.getNameIdMapCache(entityManager).get(profilename.trim());
        if (id != null) {
            returnval = id.intValue();
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfileId(" + profilename + "): " + returnval);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getEndEntityProfileName(final AuthenticationToken admin, final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfilename(" + id + ")");
        }
        final String returnval = profileCache.getIdNameMapCache(entityManager).get(Integer.valueOf(id));
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfilename(" + id + "): " + returnval);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getEndEntityProfileIdToNameMap(final AuthenticationToken admin) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getEndEntityProfileIdToNameMap");
        }
        return profileCache.getIdNameMapCache(entityManager);
    }

    @Override
    public void initializeAndUpgradeProfiles(final AuthenticationToken admin) {
    	final Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
    	final Iterator<EndEntityProfileData> iter = result.iterator();
        while (iter.hasNext()) {
        	final EndEntityProfileData pdata = iter.next();
            if (LOG.isDebugEnabled()) {
            	final String name = pdata.getProfileName();
                LOG.debug("Loaded end entity profile: " + name);
            }
            pdata.upgradeProfile();
        }
        flushProfileCache();
    }

    @Override
    public void internalChangeEndEntityProfileNoFlushCache(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile) {
    	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
        if (pdl == null) {
        	final String msg = INTRES.getLocalizedMessage("ra.errorchangeprofile", profilename);
        	LOG.info(msg);
        } else {
            pdl.setProfile(profile);
            // Get the diff of what changed
            Map<Object, Object> diff = pdl.getProfile().diff(profile);
            final String msg = INTRES.getLocalizedMessage("ra.changedprofile", profilename);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
        	// Log diff
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EjbcaEventTypes.RA_EDITEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), profilename, String.valueOf(pdl.getId()), details);
        }
    }

    @Override
    public void removeEndEntityProfile(final AuthenticationToken admin, final String profilename) {
    	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
    	try {
    		if (pdl == null) {
    			if (LOG.isDebugEnabled()) {
    				LOG.debug("Trying to remove an end entity profile that does not exist: "+profilename);                		
    			}
    		} else {
    			entityManager.remove(pdl);
    			flushProfileCache();
    			final String msg = INTRES.getLocalizedMessage("ra.removedprofile", profilename);
    			final Map<String, Object> details = new LinkedHashMap<String, Object>();
    			details.put("msg", msg);
    			auditSession.log(EjbcaEventTypes.RA_REMOVEEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), profilename, String.valueOf(pdl.getId()), details);
    		}
    	} catch (Exception e) {
    		LOG.error("Error was caught when trying to remove end entity profile " + profilename, e);
    		final String msg = INTRES.getLocalizedMessage("ra.errorremoveprofile", profilename);
    		final Map<String, Object> details = new LinkedHashMap<String, Object>();
    		details.put("msg", msg);
    		details.put("error", e.getMessage());
    		auditSession.log(EjbcaEventTypes.RA_REMOVEEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), profilename, String.valueOf(pdl.getId()), details);
    	}
    }

    @Override
    public void renameEndEntityProfile(final AuthenticationToken admin, final String oldprofilename, final String newprofilename) throws EndEntityProfileExistsException {
        if (newprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME) || oldprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
        	final String msg = INTRES.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
        if (EndEntityProfileData.findByProfileName(entityManager, newprofilename) == null) {
        	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, oldprofilename);
            if (pdl == null) {
            	final String msg = INTRES.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
            	LOG.info(msg);
            } else {
                pdl.setProfileName(newprofilename);
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("ra.renamedprofile", oldprofilename, newprofilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_RENAMEEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), oldprofilename, String.valueOf(pdl.getId()), details);
            }
        } else {
        	final String msg = INTRES.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
    }

    private boolean isFreeEndEntityProfileId(final int id) {
        boolean foundfree = false;
        if ( (id > 1) && (EndEntityProfileData.findById(entityManager, Integer.valueOf(id)) == null) ) {
        	foundfree = true;
        }
        return foundfree;
    }
}
