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
package org.cesecore.core.ejb.ca.store;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CertificateProfileData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.certificateprofiles.CACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfileExistsException;
import org.ejbca.core.model.ca.certificateprofiles.EndUserCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenAuthEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenEncCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.HardTokenSignCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.OCSPSignerCertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.RootCACertificateProfile;
import org.ejbca.core.model.ca.certificateprofiles.ServerCertificateProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;

/**
 * @author mikek
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateProfileSessionBean implements CertificateProfileSessionLocal, CertificateProfileSessionRemote {

    private static final Logger log = Logger.getLogger(CertificateProfileSessionBean.class);

    /** Cache of end entity profiles, with Id as keys */
    private static volatile Map<Integer, CertificateProfile> profileCache = null;
    /**
     * help variable used to control that profiles update (read from database)
     * isn't performed to often.
     */
    private static volatile long lastProfileCacheUpdateTime = -1;
    /** Cache of mappings between profileId and profileName */
    private static volatile HashMap<Integer, String> profileIdNameMapCache = null;
    /** Cache of mappings between profileName and profileId */
    private static volatile Map<String, Integer> profileNameIdMapCache = null;

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private LogSessionLocal logSession;

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin
     *            administrator performing the task
     * @param certificateprofileid
     *            internal ID of new certificate profile, use only if you know
     *            it's right.
     * @param certificateprofilename
     *            readable name of new certificate profile
     * @param certificateprofile
     *            the profile to be added
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename, CertificateProfile certificateprofile)
            throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(certificateprofilename)) {
            String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", certificateprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }

        if (isFreeCertificateProfileId(certificateprofileid)) {
            if (CertificateProfileData.findByProfileName(entityManager, certificateprofilename) != null) {
                String msg = intres.getLocalizedMessage("store.errorcertprofileexists", certificateprofilename);
                throw new CertificateProfileExistsException(msg);
            } else {
                try {
                    entityManager.persist(new CertificateProfileData(new Integer(certificateprofileid), certificateprofilename, certificateprofile));
                    flushProfileCache();
                    String msg = intres.getLocalizedMessage("store.addedcertprofile", certificateprofilename);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                            LogConstants.EVENT_INFO_CERTPROFILE, msg);
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("store.errorcreatecertprofile", certificateprofilename);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                            LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                }
            }
        }
    }

    /**
     * Adds a certificate profile to the database.
     * 
     * @param admin
     *            administrator performing the task
     * @param certificateprofilename
     *            readable name of new certificate profile
     * @param certificateprofile
     *            the profile to be added
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile)
            throws CertificateProfileExistsException {
        addCertificateProfile(admin, findFreeCertificateProfileId(), certificateprofilename, certificateprofile);
    }

    /**
     * Updates certificateprofile data
     * 
     * @param admin
     *            Administrator performing the operation
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) {
        internalChangeCertificateProfileNoFlushCache(admin, certificateprofilename, certificateprofile);
        flushProfileCache();
    }
    
    /**
    /** Do not use, use changeCertificateProfile instead.
     * Used internally for testing only. Updates a profile without flushing caches.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void internalChangeCertificateProfileNoFlushCache(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) {
        CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
        if (pdl != null) {
            pdl.setCertificateProfile(certificateprofile);
                String msg = intres.getLocalizedMessage("store.editedprofile", certificateprofilename);                 
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
        } else {
                String msg = intres.getLocalizedMessage("store.erroreditprofile", certificateprofilename);              
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        }
    }

    /**
     * Clear and reload certificate profile caches.
     */
    public void flushProfileCache() {
        if (log.isTraceEnabled()) {
            log.trace(">flushProfileCache");
        }
        HashMap<Integer, String> idNameCache = new HashMap<Integer, String>();
        HashMap<String, Integer> nameIdCache = new HashMap<String, Integer>();
        HashMap<Integer, CertificateProfile> profCache = new HashMap<Integer, CertificateProfile>();

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
            Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
            if (log.isDebugEnabled()) {
                log.debug("Found " + result.size() + " certificate profiles.");
            }
            Iterator<CertificateProfileData> i = result.iterator();
            while (i.hasNext()) {
                CertificateProfileData next = i.next();
                idNameCache.put(next.getId(), next.getCertificateProfileName());
                nameIdCache.put(next.getCertificateProfileName(), next.getId());
                profCache.put(next.getId(), next.getCertificateProfile());
            }
        } catch (Exception e) {
            log.error("Error reading certificate profiles: ", e);
        }
        profileIdNameMapCache = idNameCache;
        profileNameIdMapCache = nameIdCache;
        profileCache = profCache;
        lastProfileCacheUpdateTime = System.currentTimeMillis();
        if (log.isDebugEnabled()) {
            log.debug("Flushed profile cache.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<flushProfileCache");
        }
    } // flushProfileCache

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param certprofiletype should be either CertificateDataBean.CERTTYPE_ENDENTITY, CertificateDataBean.CERTTYPE_SUBCA, CertificateDataBean.CERTTYPE_ROOTCA,
     *                        CertificateDataBean.CERTTYPE_HARDTOKEN (i.e EndEntity certificates and Hardtoken fixed profiles) or 0 for all.
     *                        Retrives certificate profile names sorted.
     * @param authorizedCaIds Collection<Integer> of authorized CA Ids for the specified Admin
     * @return Collection of id:s (Integer)
     */
    public Collection<Integer> getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype, Collection<Integer> authorizedCaIds) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        HashSet<Integer> authorizedcaids = new HashSet<Integer>(authorizedCaIds);

        // Add fixed certificate profiles.
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ENDENTITY || certprofiletype == SecConst.CERTTYPE_HARDTOKEN){
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_OCSPSIGNER));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SERVER));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_SUBCA) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ROOTCA) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_HARDTOKEN) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
        }
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext()) {
                CertificateProfileData next = i.next();
                CertificateProfile profile = next.getCertificateProfile();
                // Check if all profiles available CAs exists in authorizedcaids.
                if (certprofiletype == 0 || certprofiletype == profile.getType()
                                || (profile.getType() == SecConst.CERTTYPE_ENDENTITY &&
                                                certprofiletype == SecConst.CERTTYPE_HARDTOKEN)) {
                        Iterator<Integer> availablecas = profile.getAvailableCAs().iterator();
                        boolean allexists = true;
                        while (availablecas.hasNext()) {
                                Integer nextcaid = availablecas.next();
                                if (nextcaid.intValue() == CertificateProfile.ANYCA) {
                                        allexists = true;
                                        break;
                                }
                                if (!authorizedcaids.contains(nextcaid)) {
                                        allexists = false;
                                        break;
                                }
                        }
                        if (allexists) {
                                returnval.add(next.getId());
                        }
                }
        }
        return returnval;
    }
    
    /**
     * Finds a certificate profile by id.
     * 
     * @param admin
     *            Administrator performing the operation
     * @return CertificateProfiles or null if it can not be found.
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificateProfile(" + id + ")");
        }
        CertificateProfile returnval = null;
        if (id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            switch (id) {
            case SecConst.CERTPROFILE_FIXED_ENDUSER:
                returnval = new EndUserCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_SUBCA:
                returnval = new CACertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_ROOTCA:
                returnval = new RootCACertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_OCSPSIGNER:
                returnval = new OCSPSignerCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_SERVER:
                returnval = new ServerCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH:
                returnval = new HardTokenAuthCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC:
                returnval = new HardTokenAuthEncCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_HARDTOKENENC:
                returnval = new HardTokenEncCertificateProfile();
                break;
            case SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN:
                returnval = new HardTokenSignCertificateProfile();
                break;
            default:
                returnval = new EndUserCertificateProfile();
            }
        } else {
            returnval = getProfileCacheInternal().get(Integer.valueOf(id));
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertificateProfile(" + id + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    /**
     * Retrieves a named certificate profile or null if none was found.
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) {
        Integer id = getCertificateProfileNameIdMapInternal().get(certificateprofilename);
        if (id != null) {
            return getCertificateProfile(admin, id);
        } else {
            return null;
        }
    }

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     * 
     * @param admin
     *            Administrator performing the operation
     */
    public HashMap<Integer, String> getCertificateProfileIdToNameMap(Admin admin) {
        if (log.isTraceEnabled()) {
            log.trace("><getCertificateProfileIdToNameMap");
        }
        return getCertificateProfileIdNameMapInternal();
    }

    /**
     * Adds a certificateprofile with the same content as the original
     * certificateprofile,
     * 
     * @param admin
     *            Administrator performing the operation
     * @param originalcertificateprofilename
     *            readable name of old certificate profile
     * @param newcertificateprofilename
     *            readable name of new certificate profile
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename,
            Collection<Integer> authorizedCaIds) throws CertificateProfileExistsException {
        CertificateProfile certificateprofile = null;

        if (isCertificateProfileNameFixed(newcertificateprofilename)) {
            String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", newcertificateprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }

        try {
            certificateprofile = (CertificateProfile) getCertificateProfile(admin, originalcertificateprofilename).clone();

            boolean issuperadministrator = false;
            try {
                issuperadministrator = authorizationSession.isAuthorizedNoLog(admin, "/super_administrator");
            } catch (AuthorizationDeniedException ade) {
            }

            if (!issuperadministrator && certificateprofile.isApplicableToAnyCA()) {
                // Not superadministrator, do not use ANYCA;
                certificateprofile.setAvailableCAs(authorizedCaIds);
            }

            if (CertificateProfileData.findByProfileName(entityManager, newcertificateprofilename) != null) {
                String msg = intres.getLocalizedMessage("store.erroraddprofilewithtempl", newcertificateprofilename, originalcertificateprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                throw new CertificateProfileExistsException();
            } else {
                entityManager.persist(new CertificateProfileData(findFreeCertificateProfileId(), newcertificateprofilename, certificateprofile));
                flushProfileCache();
                String msg = intres.getLocalizedMessage("store.addedprofilewithtempl", newcertificateprofilename, originalcertificateprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE,
                        msg);
            }
        } catch (CloneNotSupportedException f) {
            throw new EJBException(f); // If this happens it's a programming
            // error. Throw an exception!
        }
    }

    /**
     * Returns a certificate profile id, given it's certificate profile name
     * 
     * @param admin
     *            Administrator performing the operation
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificateProfileId: " + certificateprofilename);
        }
        int returnval = 0;
        Integer id = getCertificateProfileNameIdMapInternal().get(certificateprofilename);
        if (id != null) {
            returnval = id.intValue();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getCertificateProfileId: " + certificateprofilename + "): " + returnval);
        }
        return returnval;
    }

    /**
     * Returns a certificateprofiles name given it's id.
     * 
     * @param admin
     *            Administrator performing the operation
     * @return certificateprofilename or null if certificateprofile id doesn't
     *         exists.
     */
    public String getCertificateProfileName(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getCertificateProfileName: " + id);
        }
        String returnval = null;
        returnval = getCertificateProfileIdNameMapInternal().get(Integer.valueOf(id));
        if (log.isTraceEnabled()) {
            log.trace("<getCertificateProfileName: " + id + "): " + returnval);
        }
        return returnval;
    }

    /**
     * Renames a certificateprofile
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename)
            throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(newcertificateprofilename)) {
            String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", newcertificateprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (isCertificateProfileNameFixed(oldcertificateprofilename)) {
            String msg = intres.getLocalizedMessage("store.errorcertprofilefixed", oldcertificateprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (CertificateProfileData.findByProfileName(entityManager, newcertificateprofilename) != null) {
            String msg = intres.getLocalizedMessage("store.errorcertprofileexists", newcertificateprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException();
        } else {
            CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, oldcertificateprofilename);
            if (pdl != null) {
                pdl.setCertificateProfileName(newcertificateprofilename);
                flushProfileCache();
                String msg = intres.getLocalizedMessage("store.renamedprofile", oldcertificateprofilename, newcertificateprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE,
                        msg);
            } else {
                String msg = intres.getLocalizedMessage("store.errorrenameprofile", oldcertificateprofilename, newcertificateprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            }
        }
    }

    /**
     * A method designed to be called at startuptime to (possibly) upgrade certificate profiles.
     * This method will read all Certificate Profiles and as a side-effect upgrade them if the version if changed for upgrade.
     * Can have a side-effect of upgrading a profile, therefore the Required transaction setting.
     * 
     * @param admin administrator calling the method
     * 
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void initializeAndUpgradeProfiles(Admin admin) {
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> iter = result.iterator();
        while(iter.hasNext()) {
                CertificateProfileData pdata = iter.next();
                String name = pdata.getCertificateProfileName();
                pdata.upgradeProfile();
                float version = pdata.getCertificateProfile().getVersion();
                log.debug("Loaded certificate profile: "+name+" with version "+version);
        }
        flushProfileCache();
    }



    /**
     * Removes a certificateprofile from the database, does not throw any errors if the profile does not exist, but it does log a message.
     *
     * @param admin Administrator performing the operation
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCertificateProfile(Admin admin, String certificateprofilename) {
        try {
                CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, certificateprofilename);
                entityManager.remove(pdl);
                flushProfileCache();
                String msg = intres.getLocalizedMessage("store.removedprofile", certificateprofilename);                
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
        } catch (Exception e) {
                String msg = intres.getLocalizedMessage("store.errorremoveprofile", certificateprofilename);                    
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        }
    }
    
    /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param admin Administrator performing the operation
     * @param caid  the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid) {
        boolean exists = false;
        Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        Iterator<CertificateProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
                CertificateProfileData cd = i.next();
                CertificateProfile certProfile = cd.getCertificateProfile(); 
                if (certProfile.getType() == CertificateProfile.TYPE_ENDENTITY) {
                        Iterator<Integer> availablecas = certProfile.getAvailableCAs().iterator();
                        while (availablecas.hasNext()) {
                                if (availablecas.next().intValue() == caid ) {
                                        exists = true;
                                        log.debug("CA exists in certificate profile "+cd.getCertificateProfileName());
                                        break;
                                }
                        }
                }
        }
        return exists;
    }
    
    private Map<Integer, CertificateProfile> getProfileCacheInternal() {
        if ((profileCache == null) || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheCertificateProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileCache;
    }

    private HashMap<Integer, String> getCertificateProfileIdNameMapInternal() {
        if ((profileIdNameMapCache == null)
                || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheCertificateProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileIdNameMapCache;
    }

    private Map<String, Integer> getCertificateProfileNameIdMapInternal() {
        if ((profileNameIdMapCache == null)
                || (lastProfileCacheUpdateTime + EjbcaConfiguration.getCacheCertificateProfileTime() < System.currentTimeMillis())) {
            flushProfileCache();
        }
        return profileNameIdMapCache;
    }

    private boolean isCertificateProfileNameFixed(String certificateprofilename) {
        boolean returnval = false;
        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (certificateprofilename.equals(ServerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        return returnval;
    }

    public int findFreeCertificateProfileId() {
        Random random = new Random((new Date()).getTime());
        int id = random.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
            if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
                if (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null) {
                    foundfree = true;
                }
            } else {
                id = random.nextInt();
            }
        }
        return id;
    }

    private boolean isFreeCertificateProfileId(int id) {
        boolean foundfree = false;
        if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            if (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null) {
                foundfree = true;
            }
        }
        return foundfree;
    }

}
