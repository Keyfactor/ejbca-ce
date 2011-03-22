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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.Timeout;
import javax.ejb.Timer;
import javax.ejb.TimerService;
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
import org.ejbca.core.ejb.ca.store.CertificateProfileCache;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
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

/** Bean managing certificate profiles.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateProfileSessionBean implements CertificateProfileSessionLocal, CertificateProfileSessionRemote {

    private static final Logger LOG = Logger.getLogger(CertificateProfileSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    /** Cache of certificate profiles and id-name mappings */
    private static final CertificateProfileCache profileCache = new CertificateProfileCache();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;
    private TimerService timerService;	// When the sessionContext is injected, the timerService should be looked up.

    @EJB
    private AuthorizationSessionLocal authSession;
    @EJB
    private LogSessionLocal logSession;
    private CertificateProfileSessionLocal certificateProfileSession;
    
    private static final String CACHE_TIMER_ID = "certificateProfileCacheTimer";
    
    @PostConstruct
    public void postConstruct() {
    	certificateProfileSession = sessionContext.getBusinessObject(CertificateProfileSessionLocal.class);
    	timerService = sessionContext.getTimerService();
    }
    
    @Override
    public void addCacheTimer(final boolean initial) {
    	cancelOldTimer();
    	if (EjbcaConfiguration.getCacheCertificateProfileTime() > 0) {
    		if (initial) {
        		timerService.createTimer(0, CACHE_TIMER_ID);
    		} else {
        		timerService.createTimer(EjbcaConfiguration.getCacheCertificateProfileTime(), CACHE_TIMER_ID);
    		}
    	}
    }
    
    private void cancelOldTimer() {
    	for (Object o : timerService.getTimers()) {
    		final Timer t = (Timer) o;
    		if (CACHE_TIMER_ID.equals(t.getInfo())) {
    			t.cancel();
    			break;
    		}
    	}
    }
    
    @Timeout
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler(Timer timer) {
    	certificateProfileSession.flushProfileCache();
    	certificateProfileSession.addCacheTimer(false);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addCertificateProfile(final Admin admin, final int profileid, final String profilename, final CertificateProfile profile)
            throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(profilename)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", profilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }

        if (isFreeCertificateProfileId(profileid)) {
            if (CertificateProfileData.findByProfileName(entityManager, profilename) == null) {
                try {
                    entityManager.persist(new CertificateProfileData(Integer.valueOf(profileid), profilename, profile));
                    flushProfileCache();
                    final String msg = INTRES.getLocalizedMessage("store.addedcertprofile", profilename);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null,
                            LogConstants.EVENT_INFO_CERTPROFILE, msg);
                } catch (Exception e) {
                    final String msg = INTRES.getLocalizedMessage("store.errorcreatecertprofile", profilename);
                    logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null,
                            LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                }
            } else {
            	final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", profilename);
                throw new CertificateProfileExistsException(msg);
            }
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addCertificateProfile(final Admin admin, final String profilename, final CertificateProfile profile)
            throws CertificateProfileExistsException {
        addCertificateProfile(admin, findFreeCertificateProfileId(), profilename, profile);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void changeCertificateProfile(final Admin admin, final String profilename, final CertificateProfile profile) {
        internalChangeCertificateProfileNoFlushCache(admin, profilename, profile);
        flushProfileCache();
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void internalChangeCertificateProfileNoFlushCache(final Admin admin, final String profilename, final CertificateProfile profile) {
        final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, profilename);
        if (pdl == null) {
            final String msg = INTRES.getLocalizedMessage("store.erroreditprofile", profilename);              
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        } else {
        	pdl.setCertificateProfile(profile);
        	final String msg = INTRES.getLocalizedMessage("store.editedprofile", profilename);                 
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
        }
    }

    @Override
    public void flushProfileCache() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flushProfileCache");
        }
        profileCache.updateProfileCache(entityManager);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Flushed profile cache.");
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<flushProfileCache");
        }
    }

    @Override
    public Collection<Integer> getAuthorizedCertificateProfileIds(final Admin admin, final int certprofiletype, final Collection<Integer> authorizedCaIds) {
        final ArrayList<Integer> returnval = new ArrayList<Integer>();
        final HashSet<Integer> authorizedcaids = new HashSet<Integer>(authorizedCaIds);

        // Add fixed certificate profiles.
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ENDENTITY || certprofiletype == SecConst.CERTTYPE_HARDTOKEN){
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ENDUSER));
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_OCSPSIGNER));
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SERVER));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_SUBCA) {
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_SUBCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ROOTCA) {
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_ROOTCA));
        }
        if (certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_HARDTOKEN) {
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
            returnval.add(Integer.valueOf(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
        }
        final Map<Integer, CertificateProfile> profileCache = getProfileCacheInternal();
        for (Entry<Integer,CertificateProfile> cpEntry : profileCache.entrySet()) {
        	final CertificateProfile profile = cpEntry.getValue();
        	// Check if all profiles available CAs exists in authorizedcaids.
        	if (certprofiletype == 0 || certprofiletype == profile.getType() || (profile.getType() == SecConst.CERTTYPE_ENDENTITY &&
        					certprofiletype == SecConst.CERTTYPE_HARDTOKEN)) {
        		boolean allexists = true;
        		for (final Integer nextcaid : profile.getAvailableCAs()) {
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
        			returnval.add(cpEntry.getKey());
        		}
        	}
        }
        return returnval;
    }
    
    @Override
    public CertificateProfile getCertificateProfile(final Admin admin, final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfile(" + id + ")");
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
    		// We need to clone the profile, otherwise the cache contents will be modifyable from the outside
        	CertificateProfile cprofile = getProfileCacheInternal().get(Integer.valueOf(id));
    		try {
    			if (cprofile != null) {
    				returnval = (CertificateProfile)cprofile.clone();
    			}
    		} catch (CloneNotSupportedException e) {
    			LOG.error("Should never happen: ", e);
    			throw new RuntimeException(e);
    		}
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfile(" + id + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @Override
    public CertificateProfile getCertificateProfile(final Admin admin, final String profilename) {
        final Integer id = getCertificateProfileNameIdMapInternal().get(profilename);
        if (id == null) {
            return null;
        } else {
            return getCertificateProfile(admin, id);
        }
    }

    @Override
    public Map<Integer, String> getCertificateProfileIdToNameMap(final Admin admin) {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getCertificateProfileIdToNameMap");
        }
        return getCertificateProfileIdNameMapInternal();
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void cloneCertificateProfile(final Admin admin, final String orgprofilename, final String newprofilename,
            final Collection<Integer> authorizedCaIds) throws CertificateProfileExistsException {
        CertificateProfile profile = null;
        if (isCertificateProfileNameFixed(newprofilename)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", newprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }
        try {
            profile = (CertificateProfile) getCertificateProfile(admin, orgprofilename).clone();
            boolean issuperadmin = false;
            issuperadmin = authSession.isAuthorizedNoLog(admin, "/super_administrator");
            if (!issuperadmin && profile.isApplicableToAnyCA()) {
                // Not superadministrator, do not use ANYCA;
                profile.setAvailableCAs(authorizedCaIds);
            }
            if (CertificateProfileData.findByProfileName(entityManager, newprofilename) == null) {
                entityManager.persist(new CertificateProfileData(findFreeCertificateProfileId(), newprofilename, profile));
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("store.addedprofilewithtempl", newprofilename, orgprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
            } else {
                final String msg = INTRES.getLocalizedMessage("store.erroraddprofilewithtempl", newprofilename, orgprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null,
                        LogConstants.EVENT_ERROR_CERTPROFILE, msg);
                throw new CertificateProfileExistsException();
            }
        } catch (CloneNotSupportedException f) {
            throw new EJBException(f); // If this happens it's a programming error. Throw an exception!
        }
    }

    @Override
    public int getCertificateProfileId(final Admin admin, final String certificateprofilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileId: " + certificateprofilename);
        }
        int returnval = 0;
        final Integer id = getCertificateProfileNameIdMapInternal().get(certificateprofilename);
        if (id != null) {
            returnval = id.intValue();
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileId: " + certificateprofilename + "): " + returnval);
        }
        return returnval;
    }

    @Override
    public String getCertificateProfileName(final Admin admin, final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileName: " + id);
        }
        final String returnval = getCertificateProfileIdNameMapInternal().get(Integer.valueOf(id));
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileName: " + id + "): " + returnval);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void renameCertificateProfile(final Admin admin, final String oldprofilename, final String newprofilename)
            throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(newprofilename)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", newprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (isCertificateProfileNameFixed(oldprofilename)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", oldprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
                    msg);
            throw new CertificateProfileExistsException(msg);
        }
        if (CertificateProfileData.findByProfileName(entityManager, newprofilename) == null) {
            final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, oldprofilename);
            if (pdl == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorrenameprofile", oldprofilename, newprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null,
                        LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            } else {
                pdl.setCertificateProfileName(newprofilename);
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("store.renamedprofile", oldprofilename, newprofilename);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", newprofilename);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            throw new CertificateProfileExistsException();
        }
    }

    /* 
     * This method will read all Certificate Profiles and as a side-effect upgrade them if the version if changed for upgrade.
     * Can have a side-effect of upgrading a profile, therefore the Required transaction setting.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void initializeAndUpgradeProfiles(final Admin admin) {
        final Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        final Iterator<CertificateProfileData> iter = result.iterator();
        while(iter.hasNext()) {
                final CertificateProfileData pdata = iter.next();
                final String name = pdata.getCertificateProfileName();
                pdata.upgradeProfile();
                final float version = pdata.getCertificateProfile().getVersion();
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Loaded certificate profile: "+name+" with version "+version);                	
                }
        }
        flushProfileCache();
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeCertificateProfile(final Admin admin, final String profilename) {
        try {
                final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, profilename);
                if (pdl == null) {
                	if (LOG.isDebugEnabled()) {
                    	LOG.debug("Trying to remove a certificate profile that does not exist: "+profilename);                		
                	}
                } else {
                	entityManager.remove(pdl);
                	flushProfileCache();
                	final String msg = INTRES.getLocalizedMessage("store.removedprofile", profilename);                
                	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_INFO_CERTPROFILE, msg);                	
                }
        } catch (Exception e) {
            LOG.error("Error was caught when trying to remove certificate profile " + profilename, e);
        	final String msg = INTRES.getLocalizedMessage("store.errorremoveprofile", profilename);                    
        	logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
        }
    }

    @Override
    public boolean existsCAInCertificateProfiles(final Admin admin, final int caid) {
    	boolean exists = false;
    	final Map<Integer, CertificateProfile> profileCache = getProfileCacheInternal();
    	for (Entry<Integer,CertificateProfile> cpEntry : profileCache.entrySet()) {
    		final CertificateProfile certProfile = cpEntry.getValue(); 
    		if (certProfile.getType() == CertificateProfile.TYPE_ENDENTITY) {
    			for (Integer availableCaId : certProfile.getAvailableCAs()) {
    				if (availableCaId.intValue() == caid) {
    					exists = true;
    					if (LOG.isDebugEnabled()) {
    						LOG.debug("CA exists in certificate profile " + cpEntry.getKey().toString());
    					}
    					break;
    				}
    			}
    		}
    	}
    	return exists;
    }

    @Override
    public boolean existsPublisherInCertificateProfiles(final Admin admin, final int publisherid) {
    	boolean exists = false;
    	final Map<Integer, CertificateProfile> profileCache = getProfileCacheInternal();
    	for (Entry<Integer,CertificateProfile> cpEntry : profileCache.entrySet()) {
    		for (Integer availablePublisherId : cpEntry.getValue().getPublisherList()) {
    			if (availablePublisherId.intValue() == publisherid) {
    				exists = true;
                    if (LOG.isDebugEnabled()) {
                    	LOG.debug("Publisher exists in certificate profile " + cpEntry.getKey().toString());
                    }
                    break;
    			}
    		}
    	}
    	return exists;
    }
    
    private Map<Integer, CertificateProfile> getProfileCacheInternal() {
        return profileCache.getProfileCache(entityManager);
    }

    private Map<Integer, String> getCertificateProfileIdNameMapInternal() {
        return profileCache.getIdNameMapCache(entityManager);
    }

    private Map<String, Integer> getCertificateProfileNameIdMapInternal() {
    	return profileCache.getNameIdMapCache(entityManager);
    }

    private boolean isCertificateProfileNameFixed(final String profilename) {
        if (profilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (profilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (profilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (profilename.equals(OCSPSignerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        if (profilename.equals(ServerCertificateProfile.CERTIFICATEPROFILENAME)) {
            return true;
        }
        return false;
    }

    @Override
    public int findFreeCertificateProfileId() {
        final Random random = new Random(new Date().getTime());
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

    private boolean isFreeCertificateProfileId(final int id) {
        boolean foundfree = false;
        if ( (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) && (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null) ) {
        	foundfree = true;
        }
        return foundfree;
    }

}
