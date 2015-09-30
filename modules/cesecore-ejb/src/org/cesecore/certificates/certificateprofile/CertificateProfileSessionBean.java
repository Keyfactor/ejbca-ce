/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;

/**
 * Bean managing certificate profiles, see CertificateProfileSession for Javadoc.
 * 
 * Version moved from EJBCA: CertificateProfileSessionBean.java 11170 2011-01-12 17:08:32Z anatom
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateProfileSessionBean implements CertificateProfileSessionLocal, CertificateProfileSessionRemote {

    private static final Logger LOG = Logger.getLogger(CertificateProfileSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private CaSessionLocal caSession;
    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int addCertificateProfile(final AuthenticationToken admin, final String name, final CertificateProfile profile)
            throws CertificateProfileExistsException, AuthorizationDeniedException {
        return addCertificateProfile(admin, findFreeCertificateProfileId(), name, profile);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int addCertificateProfile(final AuthenticationToken admin, final int id, final String name, final CertificateProfile profile)
            throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (isCertificateProfileNameFixed(name)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", name);
            LOG.info(msg);
            // Things logged:
            // adminInfo: certserno, remote ip etc
            // module (integer), CA, RA etc
            // eventTime
            // username, if the event affects a user data (not here)
            // certificate info, if the event affects a certificate (not here)
            // event id
            // log message (free text string)
            // logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE,
            // msg);
            throw new CertificateProfileExistsException(msg);
        }

        // We need to check that admin also have rights to edit certificate profiles
        authorizedToEditProfile(admin, profile, id);

        if (isFreeCertificateProfileId(id)) {
            if (CertificateProfileData.findByProfileName(entityManager, name) == null) {
                entityManager.persist(new CertificateProfileData(Integer.valueOf(id), name, profile));
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("store.addedcertprofile", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CERTPROFILE_CREATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
                return id;
            } else {
                final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                throw new CertificateProfileExistsException(msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", id);
            throw new CertificateProfileExistsException(msg);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeCertificateProfile(final AuthenticationToken admin, final String name, final CertificateProfile profile)
            throws AuthorizationDeniedException {
        internalChangeCertificateProfileNoFlushCache(admin, name, profile);
        flushProfileCache();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void internalChangeCertificateProfileNoFlushCache(final AuthenticationToken admin, final String name, final CertificateProfile profile)
            throws AuthorizationDeniedException {

        final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, name);
        if (pdl == null) {
            final String msg = INTRES.getLocalizedMessage("store.erroreditprofile", name);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERTPROFILE_EDITING, EventStatus.FAILURE, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        } else {
            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(admin, profile, pdl.getId());

            // Get the diff of what changed
            Map<Object, Object> diff = pdl.getCertificateProfile().diff(profile);
            final String msg = INTRES.getLocalizedMessage("store.editedprofile", name);
            // Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            // Do the actual change
            pdl.setCertificateProfile(profile);
            logSession.log(EventTypes.CERTPROFILE_EDITING, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        }
    }

    @Override
    public void flushProfileCache() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flushProfileCache");
        }
        CertificateProfileCache.INSTANCE.updateProfileCache(entityManager, true);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Flushed profile cache.");
        }
    } // flushProfileCache

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneCertificateProfile(final AuthenticationToken admin, final String orgname, final String newname,
            final List<Integer> authorizedCaIds) throws CertificateProfileExistsException, CertificateProfileDoesNotExistException,
            AuthorizationDeniedException {
        CertificateProfile profile = null;

        if (isCertificateProfileNameFixed(newname)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", newname);
            LOG.info(msg);
            throw new CertificateProfileExistsException(msg);
        }

        try {
            CertificateProfile p = getCertificateProfile(orgname);
            if (p == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorcertprofilenotexist", orgname);
                LOG.info(msg);
                throw new CertificateProfileDoesNotExistException(msg);
            }

            profile = (CertificateProfile) p.clone();
            if (authorizedCaIds != null) {
                profile.setAvailableCAs(authorizedCaIds);
            }

            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(admin, profile, getCertificateProfileId(orgname));

            if (CertificateProfileData.findByProfileName(entityManager, newname) == null) {
                entityManager.persist(new CertificateProfileData(findFreeCertificateProfileId(), newname, profile));
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("store.addedprofilewithtempl", newname, orgname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CERTPROFILE_CREATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
            } else {
                final String msg = INTRES.getLocalizedMessage("store.erroraddprofilewithtempl", newname, orgname);
                throw new CertificateProfileExistsException(msg);
            }
        } catch (CloneNotSupportedException f) {
            // If this happens it's a programming error. Throw an exception!
            throw new EJBException(f);
        }
    }
    
    @Override
    public List<Integer> getAuthorizedCertificateProfileIds(final AuthenticationToken admin, final int certprofiletype) {
        final ArrayList<Integer> returnval = new ArrayList<Integer>();
        final HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAuthorizedCaIds(admin));
        final HashSet<Integer> allcaids = new HashSet<Integer>(caSession.getAllCaIds());

        // Add fixed certificate profiles.
        if (certprofiletype == 0 || certprofiletype == CertificateConstants.CERTTYPE_ENDENTITY
                || certprofiletype == CertificateConstants.CERTTYPE_HARDTOKEN) {
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER));
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER));
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER));
        }
        if (certprofiletype == 0 || certprofiletype == CertificateConstants.CERTTYPE_SUBCA) {
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA));
        }
        if (certprofiletype == 0 || certprofiletype == CertificateConstants.CERTTYPE_ROOTCA) {
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA));
        }
        if (certprofiletype == 0 || certprofiletype == CertificateConstants.CERTTYPE_HARDTOKEN) {
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTH));
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENENC));
            returnval.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_HARDTOKENSIGN));
        }
        final boolean rootAccess = accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource());
        for (final Entry<Integer,CertificateProfile> cpEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
                final CertificateProfile profile = cpEntry.getValue();
                // Check if all profiles available CAs exists in authorizedcaids.          
                if (certprofiletype == 0 || certprofiletype == profile.getType() || (profile.getType() == CertificateConstants.CERTTYPE_ENDENTITY &&
                        certprofiletype == CertificateConstants.CERTTYPE_HARDTOKEN)) {
                boolean allexists = true;
                for (final Integer nextcaid : profile.getAvailableCAs()) {
                    if (nextcaid.intValue() == CertificateProfile.ANYCA) {
                        allexists = true;
                        break;
                    }
                    // superadmin should be able to access profiles with missing CA Ids
                    if (!authorizedcaids.contains(nextcaid) && (!rootAccess || allcaids.contains(nextcaid))) {
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
    } // getAuthorizedCertificateProfileIds
    
    @Override
    public List<Integer> getAuthorizedCertificateProfileWithMissingCAs(final AuthenticationToken admin) {
        final ArrayList<Integer> returnval = new ArrayList<Integer>();
        if (!accessSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
            return returnval;
        }
        
        final HashSet<Integer> allcaids = new HashSet<Integer>(caSession.getAllCaIds());
        allcaids.add(CertificateProfile.ANYCA);
        for (final Entry<Integer,CertificateProfile> cpEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            final CertificateProfile profile = cpEntry.getValue();
            boolean nonExistingCA = false;
            for (final Integer caid : profile.getAvailableCAs()) {
                if (!allcaids.contains(caid)) {
                    nonExistingCA = true;
                    break;
                }
            }
            if (nonExistingCA) {
                returnval.add(cpEntry.getKey());
            }
        }
        return returnval;
    } // getAuthorizedCertificateProfileWithMissingCAs

    @Override
    public CertificateProfile getCertificateProfile(final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfile(" + id + ")");
        }
        CertificateProfile returnval = null;
        if (id < CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            returnval = new CertificateProfile(id);
        } else {
            // We need to clone the profile, otherwise the cache contents will be modifyable from the outside
            final CertificateProfile cprofile = CertificateProfileCache.INSTANCE.getProfileCache(entityManager).get(Integer.valueOf(id));
            try {
                if (cprofile != null) {
                    returnval = (CertificateProfile) cprofile.clone();
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
    public Map<Integer, CertificateProfile> getAllCertificateProfiles() {
        return CertificateProfileCache.INSTANCE.getProfileCache(entityManager);
    }

    @Override
    public CertificateProfile getCertificateProfile(final String name) {
        final Integer id = CertificateProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(name);
        if (id == null) {
            return null;
        } else {
            return getCertificateProfile(id);
        }
    }

    @Override
    public int getCertificateProfileId(final String certificateprofilename) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileId: " + certificateprofilename);
        }
        int returnval = 0;
        final Integer id = CertificateProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(certificateprofilename);
        if (id != null) {
            returnval = id.intValue();
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileId: " + certificateprofilename + "): " + returnval);
        }
        return returnval;
    }

    @Override
    public String getCertificateProfileName(final int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileName: " + id);
        }
        final String returnval = CertificateProfileCache.INSTANCE.getIdNameMapCache(entityManager).get(Integer.valueOf(id));
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileName: " + id + "): " + returnval);
        }
        return returnval;
    }

    @Override
    public Map<Integer, String> getCertificateProfileIdToNameMap() {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getCertificateProfileIdToNameMap");
        }
        return CertificateProfileCache.INSTANCE.getIdNameMapCache(entityManager);
    }

    /* 
     * This method will read all Certificate Profiles and as a side-effect upgrade them if the version if changed for upgrade.
     * Can have a side-effect of upgrading a profile, therefore the Required transaction setting.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void initializeAndUpgradeProfiles() {
        final Collection<CertificateProfileData> result = CertificateProfileData.findAll(entityManager);
        final Iterator<CertificateProfileData> iter = result.iterator();
        while (iter.hasNext()) {
            final CertificateProfileData pdata = iter.next();
            final String name = pdata.getCertificateProfileName();
            pdata.upgradeProfile();
            final float version = pdata.getCertificateProfile().getVersion();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loaded certificate profile: " + name + " with version " + version);
            }
        }
        flushProfileCache();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameCertificateProfile(final AuthenticationToken admin, final String oldname, final String newname)
            throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (isCertificateProfileNameFixed(newname)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", newname);
            throw new CertificateProfileExistsException(msg);
        }
        if (isCertificateProfileNameFixed(oldname)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", oldname);
            throw new CertificateProfileExistsException(msg);
        }
        if (CertificateProfileData.findByProfileName(entityManager, newname) == null) {
            final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, oldname);
            if (pdl == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorrenameprofile", oldname, newname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CERTPROFILE_RENAMING, EventStatus.FAILURE, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
            } else {
                // We need to check that admin also have rights to edit certificate profiles
                authorizedToEditProfile(admin, pdl.getCertificateProfile(), pdl.getId());

                pdl.setCertificateProfileName(newname);
                flushProfileCache();
                final String msg = INTRES.getLocalizedMessage("store.renamedprofile", oldname, newname);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CERTPROFILE_RENAMING, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", newname);
            throw new CertificateProfileExistsException(msg);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCertificateProfile(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        final CertificateProfileData pdl = CertificateProfileData.findByProfileName(entityManager, name);
        if (pdl == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove a certificate profile that does not exist: " + name);
            }
        } else {
            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(admin, pdl.getCertificateProfile(), pdl.getId());

            entityManager.remove(pdl);
            flushProfileCache();
            final String msg = INTRES.getLocalizedMessage("store.removedprofile", name);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CERTPROFILE_DELETION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        }
    }

    @Override
    public boolean existsCAIdInCertificateProfiles(final int caid) {
        for (final Entry<Integer,CertificateProfile> cpEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            final CertificateProfile certProfile = cpEntry.getValue();
            if (certProfile.getType() == CertificateConstants.CERTTYPE_ENDENTITY) {
                for (Integer availableCaId : certProfile.getAvailableCAs()) {
                    if (availableCaId.intValue() == caid) {                      
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("CA exists in certificate profile " + cpEntry.getKey().toString());
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    @Override
    public boolean existsPublisherIdInCertificateProfiles(final int publisherid) {
        for (final Entry<Integer,CertificateProfile> cpEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            for (Integer availablePublisherId : cpEntry.getValue().getPublisherList()) {
                if (availablePublisherId.intValue() == publisherid) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Publisher exists in certificate profile " + cpEntry.getKey().toString());
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isCertificateProfileNameFixed(final String profilename) {
        if (CertificateProfile.FIXED_PROFILENAMES.contains(profilename)) {
            return true;
        }
        return false;
    }

    private int findFreeCertificateProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return CertificateProfileData.findById(entityManager, Integer.valueOf(i))==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    private boolean isFreeCertificateProfileId(final int id) {
        boolean foundfree = false;
        if ((id > CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY)
                && (CertificateProfileData.findById(entityManager, Integer.valueOf(id)) == null)) {
            foundfree = true;
        }
        return foundfree;
    }

    private void authorizedToEditProfile(AuthenticationToken admin, CertificateProfile profile, int id) throws AuthorizationDeniedException {
        final Collection<Integer> ids = profile.getAvailableCAs();
        final String[] rules = new String[ids.size()+1];
        // We need to check that admin also have rights to edit certificate profiles
        rules[0] = StandardRules.CERTIFICATEPROFILEEDIT.resource();
        int i=1;
        // Check that admin is authorized to all CAids
        for (Integer caid : ids) {
            rules[i++] = StandardRules.CAACCESS.resource() + caid;
        }
        // Perform authorization check
        if (!accessSession.isAuthorized(admin, rules)) {
            final String msg = INTRES.getLocalizedMessage("store.editcertprofilenotauthorized", admin.toString(), id);
            throw new AuthorizationDeniedException(msg);
        }
    }
}
