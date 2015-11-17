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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;

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

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal authSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    @Override
    public void addEndEntityProfile(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile) throws AuthorizationDeniedException, EndEntityProfileExistsException {
        addEndEntityProfile(admin, findFreeEndEntityProfileId(), profilename, profile);
    }

    @Override
    public void addEndEntityProfile(final AuthenticationToken admin, final int profileid, final String profilename, final EndEntityProfile profile) throws AuthorizationDeniedException, EndEntityProfileExistsException {
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
            // Check authorization before adding
            authorizedToProfile(admin, profile);
            try {
                entityManager.persist(new EndEntityProfileData(Integer.valueOf(profileid), profilename, profile));
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("ra.addedprofile", profilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            } catch (Exception e) {
            	final String msg = INTRES.getLocalizedMessage("ra.erroraddprofile", profilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
        }
    }

    @Override
    public void changeEndEntityProfile(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile) throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
        internalChangeEndEntityProfileNoFlushCache(admin, profilename, profile);
        flushProfileCache();
    }

    @Override
    public void cloneEndEntityProfile(final AuthenticationToken admin, final String orgname, final String newname) throws AuthorizationDeniedException, EndEntityProfileExistsException {
        if (newname.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
        	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
        if (EndEntityProfileData.findByProfileName(entityManager, newname) == null) {
        	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, orgname);
            boolean success = false;
            if (pdl != null) {
                // Check authorization before cloning
                final EndEntityProfile profile = pdl.getProfile();
                authorizedToProfile(admin, profile);
            	try {
            		final int profileid = findFreeEndEntityProfileId();
            		entityManager.persist(new EndEntityProfileData(profileid, newname, (EndEntityProfile)profile.clone()));
            		flushProfileCache();
            		final String msg = INTRES.getLocalizedMessage("ra.clonedprofile", newname, orgname);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            		success = true;
            	} catch (CloneNotSupportedException e) {
            		LOG.error("Cloe not supported?: ", e);
            	}
            }
            if (!success) {
            	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
        } else {
        	final String msg = INTRES.getLocalizedMessage("ra.errorcloneprofile", newname, orgname);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> getEndEntityProfilesUsingCertificateProfile(final int certificateProfileId) {
        String[] availprofiles = null;
        List<String> result = new ArrayList<String>();
        for(EndEntityProfileData profileData : EndEntityProfileData.findAll(entityManager)) {
            availprofiles = profileData.getProfile().getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
            for (String profileId : availprofiles) {
                if (Integer.parseInt(profileId) == certificateProfileId) {
                    result.add(profileData.getProfileName());
                    break;
                }
            }
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCAInEndEntityProfiles(final int caid) {
        String[] availablecas = null;
        boolean exists = false;
        final Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        final Iterator<EndEntityProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
        	final EndEntityProfileData ep = i.next();
            availablecas = ep.getProfile().getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
            for (int j = 0; j < availablecas.length; j++) {
                if (StringUtils.isNotEmpty(availablecas[j])) {
                    if (Integer.parseInt(availablecas[j]) == caid) {
                        exists = true;
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("CA exists in entity profile " + ep.getProfileName());
                        }
                        break;
                    }
                } else if (LOG.isDebugEnabled()) {
                    LOG.debug("One of the availableCAs is empty string, fishy, but we ignore it. EE profile: "+ep.getProfileName());
                }
            }
        }
        return exists;
    }

    @Override
    public int findFreeEndEntityProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return EndEntityProfileData.findById(EndEntityProfileSessionBean.this.entityManager, i)==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @Override
    public void flushProfileCache() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flushProfileCache");
        }
        EndEntityProfileCache.INSTANCE.updateProfileCache(entityManager, true);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Flushed profile cache");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityProfile getEndEntityProfile(final String profilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfile(" + profilename + ")");
        }
        
        EndEntityProfile returnval = getEndEntityProfileNoClone(profilename);
        try {
            if (returnval != null) {
                returnval = (EndEntityProfile)returnval.clone();
            }
        } catch (CloneNotSupportedException e) {
            LOG.error("Should never happen: ", e);
            throw new RuntimeException(e);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfile(" + profilename + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityProfile getEndEntityProfileNoClone(final String profilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfileNoClone(" + profilename + ")");
        }
        EndEntityProfile returnval = null;
        if (profilename.equals(EMPTY_ENDENTITYPROFILENAME)) {
            returnval = new EndEntityProfile(true);
        } else {
            final Integer id = EndEntityProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(profilename);
            if (id != null) {
                returnval = getEndEntityProfileNoClone(id);
            }
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfileNoClone(" + profilename + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAuthorizedEndEntityProfileIds(final AuthenticationToken admin, String endentityAccessRule) {
    	final ArrayList<Integer> returnval = new ArrayList<Integer>();
    	final HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAuthorizedCaIds(admin));
    	final HashSet<Integer> allcaids = new HashSet<Integer>(caSession.getAllCaIds());
		// If this is the special value ALLCAs we are authorized
    	authorizedcaids.add(Integer.valueOf(SecConst.ALLCAS));
    	
    	final boolean rootAccess = authSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource());
        if (authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEBASE + "/" + SecConst.EMPTY_ENDENTITYPROFILE)) {
            returnval.add(SecConst.EMPTY_ENDENTITYPROFILE);
        }
        try {
        	for (final Entry<Integer, EndEntityProfile> entry : EndEntityProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
        		// Check if all profiles available CAs exists in authorizedcaids.
        		final String availableCasString = entry.getValue().getValue(EndEntityProfile.AVAILCAS, 0);
        		if (availableCasString != null) {
        			boolean authorizedToProfile = true;
        			for (final String caidString : availableCasString.split(EndEntityProfile.SPLITCHAR)) {
        			    final int caIdInt = Integer.parseInt(caidString);
        			    // with root rule access you can edit profiles with missing CA ids
        				if (!authorizedcaids.contains(caIdInt) && (!rootAccess || allcaids.contains(caIdInt))) {
        					authorizedToProfile = false;
        					if (LOG.isDebugEnabled()) {
        						LOG.debug("Profile " + entry.getKey().toString() + " not authorized to CA with ID " + caIdInt);
        					}
        					break;
        				}
        			}
                    if (authorizedToProfile) {
                        returnval.add(entry.getKey());
                    }
        		}
        	}
        } catch (NumberFormatException e) {
            throw new IllegalStateException("CA ID was store in an end entity profile as something other than a number.", e);
        }
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAuthorizedEndEntityProfileIdsWithMissingCAs(final AuthenticationToken admin) {
        final ArrayList<Integer> returnval = new ArrayList<Integer>();
        final HashSet<Integer> allcaids = new HashSet<Integer>(caSession.getAllCaIds());
        allcaids.add(Integer.valueOf(SecConst.ALLCAS));
        if (!authSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            // we can only see profiles with missing CA Ids if we have root rule access
            return returnval;
        }
        
        try {
            for (final Entry<Integer, EndEntityProfile> entry : EndEntityProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
                final String availableCasString = entry.getValue().getValue(EndEntityProfile.AVAILCAS, 0);
                if (availableCasString != null) {
                    boolean nonExistingCA = false;
                    for (final String caidString : availableCasString.split(EndEntityProfile.SPLITCHAR)) {
                        final int caIdInt = Integer.parseInt(caidString);
                        if (!allcaids.contains(caIdInt)) {
                            nonExistingCA = true;
                        }
                    }
                    if (nonExistingCA) {
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
    public EndEntityProfile getEndEntityProfile(final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfile(" + id + ")");
        }
        EndEntityProfile returnval = getEndEntityProfileNoClone(id);
        try {
            if (returnval != null) {
                returnval = (EndEntityProfile)returnval.clone();
            }
        } catch (CloneNotSupportedException e) {
            LOG.error("Should never happen: ", e);
            throw new RuntimeException(e);
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfile(id): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityProfile getEndEntityProfileNoClone(final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfileNoClone(" + id + ")");
        }
        EndEntityProfile returnval = null;
        if (id == SecConst.EMPTY_ENDENTITYPROFILE) {
            returnval = new EndEntityProfile(true);
        } else {
            // We need to clone the profile, otherwise the cache contents will be modifyable from the outside
            returnval = EndEntityProfileCache.INSTANCE.getProfileCache(entityManager).get(Integer.valueOf(id));
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfileNoClone(id): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int getEndEntityProfileId(final String profilename) throws EndEntityProfileNotFoundException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfileId(" + profilename + ")");
        }
        final Integer id = EndEntityProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(profilename.trim());
        if (id != null) {
            int result = id.intValue();
            if (LOG.isTraceEnabled()) {
                LOG.trace("<getEndEntityProfileId(" + profilename + "): " + result);
            }
            return result;
        } else {
            throw new EndEntityProfileNotFoundException("End Entity Profile of name \"" + profilename + "\" was not found");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getEndEntityProfileName(final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getEndEntityProfilename(" + id + ")");
        }
        final String returnval = EndEntityProfileCache.INSTANCE.getIdNameMapCache(entityManager).get(Integer.valueOf(id));
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getEndEntityProfilename(" + id + "): " + returnval);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getEndEntityProfileIdToNameMap() {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getEndEntityProfileIdToNameMap");
        }
        return EndEntityProfileCache.INSTANCE.getIdNameMapCache(entityManager);
    }

    @Override
    public void initializeAndUpgradeProfiles() {
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
    public void internalChangeEndEntityProfileNoFlushCache(final AuthenticationToken admin, final String profilename, final EndEntityProfile profile)
            throws AuthorizationDeniedException, EndEntityProfileNotFoundException {
	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
        if (pdl == null) {
        	final String msg = INTRES.getLocalizedMessage("ra.errorchangeprofile", profilename);
        	LOG.info(msg);
        	throw new EndEntityProfileNotFoundException("End entity profile of name \"" + profilename + "\" not found.");
        } else {
            // Check authorization before editing
            authorizedToProfile(admin, profile);
            // Get the diff of what changed
            Map<Object, Object> diff = pdl.getProfile().diff(profile);
            pdl.setProfile(profile);      
            final String msg = INTRES.getLocalizedMessage("ra.changedprofile", profilename);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
        	// Log diff
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EjbcaEventTypes.RA_EDITEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(),
                    null, null, null, details);
        }
    }

    @Override
    public void removeEndEntityProfile(final AuthenticationToken admin, final String profilename) throws AuthorizationDeniedException {
    	final EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
    		if (pdl == null) {
    			if (LOG.isDebugEnabled()) {
    				LOG.debug("Trying to remove an end entity profile that does not exist: "+profilename);                		
    			}
    		} else {
    		    // Check authorization before removing
                authorizedToProfile(admin, pdl.getProfile());
    		    try {
    		        entityManager.remove(pdl);
    		        flushProfileCache();
    		        final String msg = INTRES.getLocalizedMessage("ra.removedprofile", profilename);
    		        final Map<String, Object> details = new LinkedHashMap<String, Object>();
    		        details.put("msg", msg);
    		        auditSession.log(EjbcaEventTypes.RA_REMOVEEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
    		    } catch (Exception e) {
    		        LOG.error("Error was caught when trying to remove end entity profile " + profilename, e);
    		        final String msg = INTRES.getLocalizedMessage("ra.errorremoveprofile", profilename);
    		        final Map<String, Object> details = new LinkedHashMap<String, Object>();
    		        details.put("msg", msg);
    		        details.put("error", e.getMessage());
    		        auditSession.log(EjbcaEventTypes.RA_REMOVEEEPROFILE, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
    		    }
    		}
    }

    @Override
    public void renameEndEntityProfile(final AuthenticationToken admin, final String oldprofilename, final String newprofilename) throws AuthorizationDeniedException, EndEntityProfileExistsException {
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
                // Check authorization before renaming
                authorizedToProfile(admin, pdl.getProfile());
                pdl.setProfileName(newprofilename);
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("ra.renamedprofile", oldprofilename, newprofilename);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_RENAMEEEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
        } else {
        	final String msg = INTRES.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
        	LOG.info(msg);
            throw new EndEntityProfileExistsException();
        }
    }

    @Override
    public void authorizedToProfileCas(final AuthenticationToken admin, final EndEntityProfile profile) throws AuthorizationDeniedException {
        if (profile == null) {
            return;
        }
        final HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAuthorizedCaIds(admin));
        final String availablecasstring = profile.getValue(EndEntityProfile.AVAILCAS, 0);
        if (StringUtils.isNotEmpty(availablecasstring)) {
            /*
             * Go through all available CAs in the profile and check
             * that the administrator is authorized to all CAs specified
             * in the profile If ALLCAS is selected in the end entity
             * profile, we must check that the administrator is
             * authorized to all CAs in the system.
             */
            String[] availablecas = profile.getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
            /*
             * If availablecas contains SecConst ALLCAS, change
             * availablecas /to be a list of all CAs
             */
            if (ArrayUtils.contains(availablecas, String.valueOf(SecConst.ALLCAS))) {
                Collection<Integer> allcaids = caSession.getAllCaIds();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Available CAs in end entity profile contains ALLCAS, lising all CAs in the system instead. There are "
                            + allcaids.size() + " CAs in the system");
                }
                availablecas = new String[allcaids.size()];
                int index = 0;
                for (Integer id : allcaids) {
                    availablecas[index++] = id.toString();
                }
            }
            for (int j = 0; j < availablecas.length; j++) {
                Integer caid = Integer.valueOf(availablecas[j]);
                if (!authorizedcaids.contains(caid)) {
                    // We want to allow removal of the EE profile if the CA does not exists, it can happen that a rogue CAId
                    // sneaks in under "availableCAs" in the profile. So make a double check here, and let it pass if the CA does not exist
                    try {
                        caSession.verifyExistenceOfCA(caid);
                        final String msg = INTRES.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
                        throw new AuthorizationDeniedException(msg);
                    } catch (CADoesntExistsException e) {
                        LOG.info("Admin was not authorized to CA "+caid+", but this CA does not even exist so we allow it.");
                    }
                }
            }
        }
    }

    private boolean isFreeEndEntityProfileId(final int id) {
        boolean foundfree = false;
        if ( (id > 1) && (EndEntityProfileData.findById(entityManager, Integer.valueOf(id)) == null) ) {
        	foundfree = true;
        }
        return foundfree;
    }
    
    /**
     * Help function that checks if administrator is authorized to edit profile.
     * @param profile is the end entity profile or null for SecConst.EMPTY_ENDENTITYPROFILE
     * @param editcheck is true for edit, add, remove, clone and rename operations. false for get.
     */    
    private void authorizedToProfile(final AuthenticationToken admin, final EndEntityProfile profile)  throws AuthorizationDeniedException {
        if (authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES) && profile != null) {
            authorizedToProfileCas(admin, profile);
        } else {
            final String msg = INTRES.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_EDITENDENTITYPROFILES, admin.toString());
            throw new AuthorizationDeniedException(msg);
        }
    }

}
