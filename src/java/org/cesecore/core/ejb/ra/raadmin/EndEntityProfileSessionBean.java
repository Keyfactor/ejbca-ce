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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;

/**
 * Session bean for handling EndEntityProfiles
 * 
 * @author mikek
 * 
 */
@Stateless(mappedName = org.ejbca.core.ejb.JndiHelper.APP_JNDI_PREFIX + "EndEntityProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityProfileSessionBean implements EndEntityProfileSessionLocal, EndEntityProfileSessionRemote {

    private static final Logger log = Logger.getLogger(EndEntityProfileSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static Random random = new Random(new Date().getTime());

    /**
     * help variable used to control that profiles update (read from database)
     * isn't performed to often.
     */
    private static volatile long lastProfileCacheUpdateTime = -1;
    /** Cache of mappings between profileId and profileName */
    private static volatile HashMap<Integer, String> profileIdNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private static volatile Map<String, Integer> profileNameIdMapCache = null;
    /** Cache of end entity profiles, with Id as keys */
    private static volatile Map<Integer, EndEntityProfile> profileCache = null;

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private LogSessionLocal logSession;

    /**
     * Adds a profile to the database.
     * 
     * @param admin
     *            administrator performing task
     * @param profilename
     *            readable profile name
     * @param profile
     *            profile to be added
     * 
     */
    public void addEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException {
        addEndEntityProfile(admin, findFreeEndEntityProfileId(), profilename, profile);
    }

    /**
     * Adds a profile to the database.
     * 
     * @param admin
     *            administrator performing task
     * @param profileid
     *            internal ID of new profile, use only if you know it's right.
     * @param profilename
     *            readable profile name
     * @param profile
     *            profile to be added
     * 
     */
    public void addEndEntityProfile(Admin admin, int profileid, String profilename, EndEntityProfile profile) throws EndEntityProfileExistsException {
        if (profilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
            String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            String error = "Attempted to add an end entity profile matching " + EMPTY_ENDENTITYPROFILENAME;
            log.error(error);
            throw new EndEntityProfileExistsException(error);
        } else if (isFreeEndEntityProfileId(profileid) == false) {
            String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            String error = "Attempted to add an end entity profile with id: " + profileid + ", which is already in the database.";
            log.error(error);
            throw new EndEntityProfileExistsException(error);
        } else if (EndEntityProfileData.findByProfileName(entityManager, profilename) != null) {
            String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            String errorMessage = "Attempted to add an end entity profile with name " + profilename + ", which already exists in the database.";
            log.error(errorMessage);
            throw new EndEntityProfileExistsException(errorMessage);
        } else {
            try {
                entityManager.persist(new EndEntityProfileData(new Integer(profileid), profilename, profile));
                flushProfileCache();
                String msg = intres.getLocalizedMessage("ra.addedprofile", profilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_ENDENTITYPROFILE, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.erroraddprofile", profilename);
                log.error(msg, e);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            }
        }
    }

    /**
     * Updates profile data
     */
    public void changeEndEntityProfile(Admin admin, String profilename, EndEntityProfile profile) {
        internalChangeEndEntityProfileNoFlushCache(admin, profilename, profile);
        flushProfileCache();
    }

    /**
     * Adds a end entity profile to a group with the same content as the
     * original profile.
     */
    public void cloneEndEntityProfile(Admin admin, String originalprofilename, String newprofilename) throws EndEntityProfileExistsException {
        if (newprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
            String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            throw new EndEntityProfileExistsException();
        }
        if (EndEntityProfileData.findByProfileName(entityManager, newprofilename) == null) {
            EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, originalprofilename);
            boolean success = false;
            if (pdl != null) {
                try {
                    entityManager.persist(new EndEntityProfileData(new Integer(findFreeEndEntityProfileId()), newprofilename, (EndEntityProfile) pdl
                            .getProfile().clone()));
                    flushProfileCache();
                    String msg = intres.getLocalizedMessage("ra.clonedprofile", newprofilename, originalprofilename);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                            LogConstants.EVENT_INFO_ENDENTITYPROFILE, msg);
                    success = true;
                } catch (Exception e) {
                }
            }
            if (!success) {
                String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            }
        } else {
            String msg = intres.getLocalizedMessage("ra.errorcloneprofile", newprofilename, originalprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            throw new EndEntityProfileExistsException();
        }
    }

    /**
     * Method to check if a certificateprofile exists in any of the end entity
     * profiles. Used to avoid desyncronization of certificate profile data.
     * 
     * @param certificateprofileid
     *            the certificatetype id to search for.
     * @return true if certificateprofile exists in any of the end entity
     *         profiles.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsCertificateProfileInEndEntityProfiles(Admin admin, int certificateprofileid) {
        String[] availablecertprofiles = null;
        boolean exists = false;
        Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        Iterator<EndEntityProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
            availablecertprofiles = i.next().getProfile().getValue(EndEntityProfile.AVAILCERTPROFILES, 0).split(EndEntityProfile.SPLITCHAR);
            for (int j = 0; j < availablecertprofiles.length; j++) {
                if (Integer.parseInt(availablecertprofiles[j]) == certificateprofileid) {
                    exists = true;
                    break;
                }
            }
        }
        return exists;
    }

    /**
     * Method to check if a CA exists in any of the end entity profiles. Used to
     * avoid desyncronization of CA data.
     * 
     * @param caid
     *            the caid to search for.
     * @return true if ca exists in any of the end entity profiles.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsCAInEndEntityProfiles(Admin admin, int caid) {
        String[] availablecas = null;
        boolean exists = false;
        Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        Iterator<EndEntityProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
            EndEntityProfileData ep = i.next();
            availablecas = ep.getProfile().getValue(EndEntityProfile.AVAILCAS, 0).split(EndEntityProfile.SPLITCHAR);
            for (int j = 0; j < availablecas.length; j++) {
                if (Integer.parseInt(availablecas[j]) == caid) {
                    exists = true;
                    if (log.isDebugEnabled()) {
                        log.debug("CA exists in entity profile " + ep.getProfileName());
                    }
                    break;
                }
            }
        }
        return exists;
    }

    public synchronized int findFreeEndEntityProfileId() {
        int id = Math.abs(random.nextInt());
        while (!(EndEntityProfileData.findById(entityManager, id) == null)) {
            Math.abs(random.nextInt());
        }
        return id;
    }

    /**
     * Clear and reload end entity profile caches.
     */
    public void flushProfileCache() {
        if (log.isTraceEnabled()) {
            log.trace(">flushProfileCache");
        }
        HashMap<Integer, String> idNameCache = new HashMap<Integer, String>();
        HashMap<String, Integer> nameIdCache = new HashMap<String, Integer>();
        HashMap<Integer, EndEntityProfile> profCache = new HashMap<Integer, EndEntityProfile>();
        idNameCache.put(new Integer(SecConst.EMPTY_ENDENTITYPROFILE), EMPTY_ENDENTITYPROFILENAME);
        nameIdCache.put(EMPTY_ENDENTITYPROFILENAME, new Integer(SecConst.EMPTY_ENDENTITYPROFILE));
        try {
            Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
            if (log.isDebugEnabled()) {
                log.debug("Found " + result.size() + " end entity profiles.");
            }
            Iterator<EndEntityProfileData> i = result.iterator();
            while (i.hasNext()) {
                EndEntityProfileData next = i.next();
                // debug("Added "+next.getId()+ ", "+next.getProfileName());
                idNameCache.put(next.getId(), next.getProfileName());
                nameIdCache.put(next.getProfileName(), next.getId());
                profCache.put(next.getId(), next.getProfile());
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("ra.errorreadprofiles");
            log.error(msg, e);
        }
        profileIdNameMapCache = idNameCache;
        profileNameIdMapCache = nameIdCache;
        profileCache = profCache;
        lastProfileCacheUpdateTime = System.currentTimeMillis();
        if (log.isDebugEnabled()) {
            log.debug("Flushed profile cache");
        }
        if (log.isTraceEnabled()) {
            log.trace("<flushProfileCache");
        }
    }

    /**
     * Finds a end entity profile by id.
     * 
     * @return EndEntityProfile or null if it does not exist
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public EndEntityProfile getEndEntityProfile(Admin admin, String profilename) {
        if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfile(" + profilename + ")");
        }
        EndEntityProfile returnval = null;
        if (profilename.equals(EMPTY_ENDENTITYPROFILENAME)) {
            returnval = new EndEntityProfile(true);
        } else {
            Integer id = (Integer) getEndEntityProfileNameIdMapInternal().get(profilename);
            returnval = (EndEntityProfile) getProfileCacheInternal().get(id);
        }
        if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfile(" + profilename + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    /**
     * Retrieves a Collection of id:s (Integer) to authorized profiles.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<Integer> getAuthorizedEndEntityProfileIds(Admin admin) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        HashSet<Integer> authorizedcaids = new HashSet<Integer>(caAdminSession.getAvailableCAs(admin));
        // debug("Admin authorized to "+authorizedcaids.size()+" CAs.");
   
        if (authorizationSession.isAuthorizedNoLog(admin, "/super_administrator")) {
            returnval.add(SecConst.EMPTY_ENDENTITYPROFILE);
        }

        try {
            Iterator<EndEntityProfileData> i = EndEntityProfileData.findAll(entityManager).iterator();
            while (i.hasNext()) {
                EndEntityProfileData next = i.next();
                // Check if all profiles available CAs exists in
                // authorizedcaids.
                String value = next.getProfile().getValue(EndEntityProfile.AVAILCAS, 0);
                // debug("AvailCAs: "+value);
                if (value != null) {
                    String[] availablecas = value.split(EndEntityProfile.SPLITCHAR);
                    // debug("No of available CAs: "+availablecas.length);
                    boolean allexists = true;
                    for (int j = 0; j < availablecas.length; j++) {
                        // debug("Available CA["+j+"]: "+availablecas[j]);
                        Integer caid = new Integer(availablecas[j]);
                        // If this is the special value ALLCAs we are authorized
                        if ((caid.intValue() != SecConst.ALLCAS) && (!authorizedcaids.contains(caid))) {
                            allexists = false;
                            if (log.isDebugEnabled()) {
                                log.debug("Profile " + next.getId() + " not authorized");
                            }
                            break;
                        }
                    }
                    if (allexists) {
                        // debug("Adding "+next.getId());
                        returnval.add(next.getId());
                    }
                }
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("ra.errorgetids");
            log.error(msg, e);
        }
        return returnval;
    }

    /**
     * Finds a end entity profile by id.
     * 
     * @return EndEntityProfile or null if it does not exist
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public EndEntityProfile getEndEntityProfile(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfile(" + id + ")");
        }
        EndEntityProfile returnval = null;
        if (id == SecConst.EMPTY_ENDENTITYPROFILE) {
            returnval = new EndEntityProfile(true);
        } else {
            returnval = (EndEntityProfile) getProfileCacheInternal().get(Integer.valueOf(id));
        }
        if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfile(id): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    /**
     * Returns a end entity profiles id, given it's profilename
     * 
     * @return the id or 0 if profile cannot be found.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getEndEntityProfileId(Admin admin, String profilename) {
        if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfileId(" + profilename + ")");
        }
        int returnval = 0;
        if (profilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
            return SecConst.EMPTY_ENDENTITYPROFILE;
        }
        Integer id = (Integer) getEndEntityProfileNameIdMapInternal().get(profilename);
        if (id != null) {
            returnval = id.intValue();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfileId(" + profilename + "): " + returnval);
        }
        return returnval;
    }

    /**
     * Returns a end entity profiles name given it's id.
     * 
     * @return profilename or null if profile id doesn't exists.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public String getEndEntityProfileName(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getEndEntityProfilename(" + id + ")");
        }
        String returnval = null;
        if (id == SecConst.EMPTY_ENDENTITYPROFILE) {
            return EMPTY_ENDENTITYPROFILENAME;
        }
        returnval = (String) getEndEntityProfileIdNameMapInternal().get(Integer.valueOf(id));
        if (log.isTraceEnabled()) {
            log.trace("<getEndEntityProfilename(" + id + "): " + returnval);
        }
        return returnval;
    }

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public HashMap<Integer, String> getEndEntityProfileIdToNameMap(Admin admin) {
        if (log.isTraceEnabled()) {
            log.trace("><getEndEntityProfileIdToNameMap");
        }
        return getEndEntityProfileIdNameMapInternal();
    }


    /**
     * A method designed to be called at startuptime to (possibly) upgrade end
     * entity profiles. This method will read all End Entity Profiles and as a
     * side-effect upgrade them if the version if changed for upgrade. Can have
     * a side-effect of upgrading a profile, therefore the Required transaction
     * setting.
     * 
     * @param admin
     *            administrator calling the method
     */
    public void initializeAndUpgradeProfiles(Admin admin) {
        Collection<EndEntityProfileData> result = EndEntityProfileData.findAll(entityManager);
        Iterator<EndEntityProfileData> iter = result.iterator();
        while (iter.hasNext()) {
            EndEntityProfileData pdata = iter.next();
            String name = pdata.getProfileName();
            pdata.upgradeProfile();
            if (log.isDebugEnabled()) {
                log.debug("Loaded end entity profile: " + name);
            }
        }
                flushProfileCache();
    }
    
    /**
     * Do not use, use changeEndEntityProfile instead. Used internally for
     * testing only. Updates a profile without flushing caches.
     */
    public void internalChangeEndEntityProfileNoFlushCache(Admin admin, String profilename, EndEntityProfile profile) {
        EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
        if (pdl != null) {
            pdl.setProfile(profile);
            String msg = intres.getLocalizedMessage("ra.changedprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_ENDENTITYPROFILE, msg);
        } else {
            String msg = intres.getLocalizedMessage("ra.errorchangeprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
        }
    }

    /**
     * Removes an end entity profile from the database.
     */
    public void removeEndEntityProfile(Admin admin, String profilename) {
        try {
            EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, profilename);
            entityManager.remove(pdl);
            flushProfileCache();
            String msg = intres.getLocalizedMessage("ra.removedprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_ENDENTITYPROFILE, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("ra.errorremoveprofile", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            log.error("Error was caught when trying to remove end entity profile " + profilename, e);
        }
    }

    /**
     * Renames a end entity profile
     */
    public void renameEndEntityProfile(Admin admin, String oldprofilename, String newprofilename) throws EndEntityProfileExistsException {
        if (newprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME) || oldprofilename.trim().equalsIgnoreCase(EMPTY_ENDENTITYPROFILENAME)) {
            String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            throw new EndEntityProfileExistsException();
        }
        if (EndEntityProfileData.findByProfileName(entityManager, newprofilename) != null) {
            String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            throw new EndEntityProfileExistsException();
        } else {
            EndEntityProfileData pdl = EndEntityProfileData.findByProfileName(entityManager, oldprofilename);
            if (pdl != null) {
                pdl.setProfileName(newprofilename);
                flushProfileCache();
                String msg = intres.getLocalizedMessage("ra.renamedprofile", oldprofilename, newprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_ENDENTITYPROFILE, msg);
            } else {
                String msg = intres.getLocalizedMessage("ra.errorrenameprofile", oldprofilename, newprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_ENDENTITYPROFILE, msg);
            }
        }
    }

    private HashMap<Integer, String> getEndEntityProfileIdNameMapInternal() {
        if ((profileIdNameMapCache == null)
                || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheEndEntityProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileIdNameMapCache;
    }

    private Map<String, Integer> getEndEntityProfileNameIdMapInternal() {
        if ((profileNameIdMapCache == null)
                || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheEndEntityProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileNameIdMapCache;
    }

    private Map<Integer, EndEntityProfile> getProfileCacheInternal() {
        if ((profileCache == null) || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheEndEntityProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileCache;
    }

    private boolean isFreeEndEntityProfileId(int id) {
        boolean foundfree = false;
        if (id > 1) {
            if (EndEntityProfileData.findById(entityManager, Integer.valueOf(id)) == null) {
                foundfree = true;
            }
        }
        return foundfree;
    }
}
