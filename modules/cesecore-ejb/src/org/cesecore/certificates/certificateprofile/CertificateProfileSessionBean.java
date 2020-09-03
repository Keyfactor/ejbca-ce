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

import java.beans.XMLEncoder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;
import org.cesecore.audit.log.dto.SecurityEventProperties;

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
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int addCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String certificateProfileName,
            final CertificateProfile certificateProfile
    ) throws CertificateProfileExistsException, AuthorizationDeniedException {
        return addCertificateProfile(authenticationToken, findFreeCertificateProfileId(), certificateProfileName, certificateProfile);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public int addCertificateProfile(
            final AuthenticationToken authenticationToken,
            final int certificateProfileId,
            final String certificateProfileName,
            final CertificateProfile certificateProfile
    ) throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (isCertificateProfileNameFixed(certificateProfileName)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", certificateProfileName);
            LOG.info(msg);
            // TODO ECA-9150 Should we log an event or just remove these lines?
            // logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_CERTPROFILE, msg);
            // logSessionEvent(
            //         EventTypes.CERTPROFILE_CREATION, EventStatus.FAILURE,
            //         authenticationToken,
            //         SecurityEventProperties.builder().withMsg(msg).build()
            // );
            throw new CertificateProfileExistsException(msg);
        }
        // We need to check that admin also have rights to edit certificate profiles
        authorizedToEditProfile(authenticationToken, certificateProfile, certificateProfileId);
        if (isFreeCertificateProfileId(certificateProfileId)) {
            if (CertificateProfileData.findByProfileName(entityManager, certificateProfileName) == null) {
                entityManager.persist(new CertificateProfileData(certificateProfileId, certificateProfileName, certificateProfile));
                flushProfileCache();
                logSessionEvent(
                        EventTypes.CERTPROFILE_CREATION, EventStatus.SUCCESS,
                        authenticationToken,
                        SecurityEventProperties.builder()
                                .withMsg(INTRES.getLocalizedMessage("store.addedcertprofile", certificateProfileName))
                                .build());
                return certificateProfileId;
            } else {
                final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", certificateProfileName);
                throw new CertificateProfileExistsException(msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofileexists", certificateProfileId);
            throw new CertificateProfileExistsException(msg);
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeCertificateProfile(
            final AuthenticationToken authenticationToken, final String certificateProfileName, final CertificateProfile certificateProfile
    ) throws AuthorizationDeniedException {
        internalChangeCertificateProfileNoFlushCache(authenticationToken, certificateProfileName, certificateProfile);
        flushProfileCache();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void internalChangeCertificateProfileNoFlushCache(
            final AuthenticationToken authenticationToken, final String certificateProfileName, final CertificateProfile certificateProfile
    ) throws AuthorizationDeniedException {
        final CertificateProfileData certificateProfileData = CertificateProfileData.findByProfileName(entityManager, certificateProfileName);
        if (certificateProfileData == null) {
            logSessionEvent(
                    EventTypes.CERTPROFILE_EDITING, EventStatus.FAILURE,
                    authenticationToken,
                    SecurityEventProperties.builder()
                            .withMsg(INTRES.getLocalizedMessage("store.erroreditprofile", certificateProfileName))
                            .build()
            );
        } else {
            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(authenticationToken, certificateProfile, certificateProfileData.getId());
            // Get the diff of what changed
            final Map<Object, Object> diff = certificateProfileData.getCertificateProfile().diff(certificateProfile);
            // Do the actual change
            certificateProfileData.setCertificateProfile(certificateProfile);
            // Log
            logSessionEvent(
                    EventTypes.CERTPROFILE_EDITING, EventStatus.SUCCESS,
                    authenticationToken,
                    SecurityEventProperties.builder()
                            .withMsg(INTRES.getLocalizedMessage("store.editedprofile", certificateProfileName))
                            .withCustomMap(diff)
                            .build()
            );
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
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String oldCertificateProfileName,
            final String newCertificateProfileName,
            final List<Integer> authorizedCaIds
    ) throws CertificateProfileExistsException, CertificateProfileDoesNotExistException, AuthorizationDeniedException {
        if (isCertificateProfileNameFixed(newCertificateProfileName)) {
            final String msg = INTRES.getLocalizedMessage("store.errorcertprofilefixed", newCertificateProfileName);
            LOG.info(msg);
            throw new CertificateProfileExistsException(msg);
        }
        try {
            final int origProfileId = getCertificateProfileId(oldCertificateProfileName);
            if (origProfileId == 0) {
                final String msg = INTRES.getLocalizedMessage("store.errorcertprofilenotexist", oldCertificateProfileName);
                LOG.info(msg);
                throw new CertificateProfileDoesNotExistException(msg);
            }
            final CertificateProfile originalCertificateProfile = getCertificateProfile(origProfileId);
            final CertificateProfile clonedCertificateProfile = originalCertificateProfile.clone();
            if (authorizedCaIds != null) {
                clonedCertificateProfile.setAvailableCAs(authorizedCaIds);
            }
            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(authenticationToken, clonedCertificateProfile, origProfileId);
            if (CertificateProfileData.findByProfileName(entityManager, newCertificateProfileName) == null) {
                entityManager.persist(new CertificateProfileData(findFreeCertificateProfileId(), newCertificateProfileName, clonedCertificateProfile));
                flushProfileCache();
                logSessionEvent(
                        EventTypes.CERTPROFILE_CREATION, EventStatus.SUCCESS,
                        authenticationToken,
                        SecurityEventProperties.builder()
                                .withMsg(INTRES.getLocalizedMessage("store.addedprofilewithtempl", newCertificateProfileName, oldCertificateProfileName))
                                .build()
                );
            } else {
                final String msg = INTRES.getLocalizedMessage("store.erroraddprofilewithtempl", newCertificateProfileName, oldCertificateProfileName);
                throw new CertificateProfileExistsException(msg);
            }
        } catch (CloneNotSupportedException f) {
            // If this happens it's a programming error. Throw an exception!
            throw new IllegalStateException(f);
        }
    }
    
    @Override
    public List<Integer> getAuthorizedCertificateProfileIds(final AuthenticationToken authenticationToken, final int certificateProfileType) {
        final ArrayList<Integer> returnValues = new ArrayList<>();
        final HashSet<Integer> authorizedCaIds = new HashSet<>(caSession.getAuthorizedCaIds(authenticationToken));
        final HashSet<Integer> allCaIds = new HashSet<>(caSession.getAllCaIds());
        // Add fixed certificate profiles.
        if (certificateProfileType == CertificateConstants.CERTTYPE_UNKNOWN || certificateProfileType == CertificateConstants.CERTTYPE_ENDENTITY) {
            returnValues.add(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            returnValues.add(CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);
            returnValues.add(CertificateProfileConstants.CERTPROFILE_FIXED_SERVER);
        }
        if (certificateProfileType == CertificateConstants.CERTTYPE_UNKNOWN || certificateProfileType == CertificateConstants.CERTTYPE_SUBCA) {
            returnValues.add(CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA);
        }
        if (certificateProfileType == CertificateConstants.CERTTYPE_UNKNOWN || certificateProfileType == CertificateConstants.CERTTYPE_ROOTCA) {
            returnValues.add(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        }
        final boolean rootAccess = authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource());
        for (final Entry<Integer,CertificateProfile> certificateProfileEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            final CertificateProfile profile = certificateProfileEntry.getValue();
            // Check if all profiles available CAs exists in authorizedcaids.
            if (certificateProfileType == 0 || certificateProfileType == profile.getType()) {
                boolean allExists = true;
                for (final Integer nextCaId : profile.getAvailableCAs()) {
                    if (nextCaId == CertificateProfile.ANYCA) {
                        break;
                    }
                    // superadmin should be able to access profiles with missing CA Ids
                    if (!authorizedCaIds.contains(nextCaId) && (!rootAccess || allCaIds.contains(nextCaId))) {
                        allExists = false;
                        break;
                    }
                }
                if (allExists) {
                    returnValues.add(certificateProfileEntry.getKey());
                }
            }
        }
        return returnValues;
    } 
    
    @Override
    public List<Integer> getAuthorizedCertificateProfileWithMissingCAs(final AuthenticationToken authenticationToken) {
        final ArrayList<Integer> returnValues = new ArrayList<>();
        if (!authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.ROLE_ROOT.resource())) {
            return returnValues;
        }
        final HashSet<Integer> allCaIds = new HashSet<>(caSession.getAllCaIds());
        allCaIds.add(CertificateProfile.ANYCA);
        for (final Entry<Integer,CertificateProfile> cpEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            final CertificateProfile profile = cpEntry.getValue();
            boolean nonExistingCA = false;
            for (final Integer caId : profile.getAvailableCAs()) {
                if (!allCaIds.contains(caId)) {
                    nonExistingCA = true;
                    break;
                }
            }
            if (nonExistingCA) {
                returnValues.add(cpEntry.getKey());
            }
        }
        return returnValues;
    }

    @Override
    public CertificateProfile getCertificateProfile(final int certificateProfileId) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfile(" + certificateProfileId + ")");
        }
        CertificateProfile returnValue = null;
        if (certificateProfileId < CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            returnValue = new CertificateProfile(certificateProfileId);
        } else {
            // We need to clone the profile, otherwise the cache contents will be modifyable from the outside
            final CertificateProfile cprofile = CertificateProfileCache.INSTANCE.getProfileCache(entityManager).get(certificateProfileId);
            try {
                if (cprofile != null) {
                    returnValue = cprofile.clone();
                }
            } catch (CloneNotSupportedException e) {
                LOG.error("Should never happen: ", e);
                throw new IllegalStateException(e);
            }
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfile(" + certificateProfileId + "): " + (returnValue == null ? "null" : "not null"));
        }
        return returnValue;
    }
    
    @Override
    public Map<Integer, CertificateProfile> getAllCertificateProfiles() {
        return CertificateProfileCache.INSTANCE.getProfileCache(entityManager);
    }

    @Override
    public CertificateProfile getCertificateProfile(final String certificateProfileName) {
        final Integer id = CertificateProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(certificateProfileName);
        if (id != null) {
            return getCertificateProfile(id);
        }
        return null;
    }

    @Override
    public int getCertificateProfileId(final String certificateProfileName) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileId: " + certificateProfileName);
        }
        int returnValue = 0;
        final Integer id = CertificateProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(certificateProfileName);
        if (id != null) {
            returnValue = id;
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileId: " + certificateProfileName + "): " + returnValue);
        }
        return returnValue;
    }

    @Override
    public String getCertificateProfileName(final int certificateProfileId) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getCertificateProfileName: " + certificateProfileId);
        }
        final String returnValue = CertificateProfileCache.INSTANCE.getIdNameMapCache(entityManager).get(certificateProfileId);
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getCertificateProfileName: " + certificateProfileId + "): " + returnValue);
        }
        return returnValue;
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
        for (CertificateProfileData certificateProfileData : result) {
            final String certificateProfileName = certificateProfileData.getCertificateProfileName();
            certificateProfileData.upgradeProfile();
            final float certificateProfileVersion = certificateProfileData.getCertificateProfile().getVersion();
            if (LOG.isDebugEnabled()) {
                LOG.debug("Loaded certificate profile: " + certificateProfileName + " with version " + certificateProfileVersion);
            }
        }
        flushProfileCache();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameCertificateProfile(
            final AuthenticationToken authenticationToken,
            final String oldCertificateProfileName,
            final String newCertificateProfileName
    ) throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (isCertificateProfileNameFixed(newCertificateProfileName)) {
            throw new CertificateProfileExistsException(INTRES.getLocalizedMessage("store.errorcertprofilefixed", newCertificateProfileName));
        }
        if (isCertificateProfileNameFixed(oldCertificateProfileName)) {
            throw new CertificateProfileExistsException(INTRES.getLocalizedMessage("store.errorcertprofilefixed", oldCertificateProfileName));
        }
        if (CertificateProfileData.findByProfileName(entityManager, newCertificateProfileName) == null) {
            final CertificateProfileData certificateProfileData = CertificateProfileData.findByProfileName(entityManager, oldCertificateProfileName);
            if (certificateProfileData == null) {
                logSessionEvent(
                        EventTypes.CERTPROFILE_RENAMING, EventStatus.FAILURE,
                        authenticationToken,
                        SecurityEventProperties.builder().withMsg(
                                INTRES.getLocalizedMessage("store.errorrenameprofile", oldCertificateProfileName, newCertificateProfileName)
                        ).build()
                );
            } else {
                // We need to check that admin also have rights to edit certificate profiles
                authorizedToEditProfile(authenticationToken, certificateProfileData.getCertificateProfile(), certificateProfileData.getId());
                certificateProfileData.setCertificateProfileName(newCertificateProfileName);
                flushProfileCache();
                logSessionEvent(
                        EventTypes.CERTPROFILE_RENAMING, EventStatus.SUCCESS,
                        authenticationToken,
                        SecurityEventProperties.builder()
                                .withMsg(INTRES.getLocalizedMessage("store.renamedprofile", oldCertificateProfileName, newCertificateProfileName))
                                .build()
                ); 
            }
        } else {
            throw new CertificateProfileExistsException(INTRES.getLocalizedMessage("store.errorcertprofileexists", newCertificateProfileName));
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeCertificateProfile(final AuthenticationToken authenticationToken, final String certificateProfileName) throws AuthorizationDeniedException {
        final CertificateProfileData certificateProfileData = CertificateProfileData.findByProfileName(entityManager, certificateProfileName);
        if (certificateProfileData == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove a certificate profile that does not exist: " + certificateProfileName);
            }
        } else {
            // We need to check that admin also have rights to edit certificate profiles
            authorizedToEditProfile(authenticationToken, certificateProfileData.getCertificateProfile(), certificateProfileData.getId());
            entityManager.remove(certificateProfileData);
            flushProfileCache();
            logSessionEvent(
                    EventTypes.CERTPROFILE_DELETION, EventStatus.SUCCESS,
                    authenticationToken,
                    SecurityEventProperties.builder()
                            .withMsg(INTRES.getLocalizedMessage("store.removedprofile", certificateProfileName))
                            .build()
            );
        }
    }

    @Override
    public boolean existsCAIdInCertificateProfiles(final int caId) {
        for (final Entry<Integer,CertificateProfile> certificateProfileEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            final CertificateProfile certificateProfile = certificateProfileEntry.getValue();
            if (certificateProfile.getType() == CertificateConstants.CERTTYPE_ENDENTITY) {
                for (Integer availableCaId : certificateProfile.getAvailableCAs()) {
                    if (availableCaId == caId) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug("CA exists in certificate profile " + certificateProfileEntry.getKey().toString());
                        }
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    @Override
    public boolean existsPublisherIdInCertificateProfiles(final int publisherId) {
        for (final Entry<Integer,CertificateProfile> certificateProfileEntry : CertificateProfileCache.INSTANCE.getProfileCache(entityManager).entrySet()) {
            for (Integer availablePublisherId : certificateProfileEntry.getValue().getPublisherList()) {
                if (availablePublisherId == publisherId) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Publisher exists in certificate profile " + certificateProfileEntry.getKey().toString());
                    }
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isCertificateProfileNameFixed(final String profilename) {
        return CertificateProfile.FIXED_PROFILENAMES.contains(profilename);
    }

    private int findFreeCertificateProfileId() {
        final ProfileID.DB profileIdDb = i -> CertificateProfileData.findById(entityManager, i) == null;
        return ProfileID.getNotUsedID(profileIdDb);
    }

    private boolean isFreeCertificateProfileId(final int id) {
        boolean foundfree = false;
        if ((id > CertificateProfileConstants.FIXED_CERTIFICATEPROFILE_BOUNDRY)
                && (CertificateProfileData.findById(entityManager, id) == null)) {
            foundfree = true;
        }
        return foundfree;
    }

    private void authorizedToEditProfile(
            final AuthenticationToken authenticationToken,
            final CertificateProfile certificateProfile,
            final int id
    ) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit certificate profiles
        if (!authorizedToProfileWithResource(
                authenticationToken,
                certificateProfile,
                true,
                StandardRules.CERTIFICATEPROFILEEDIT.resource())
        ) {
            throw new AuthorizationDeniedException(INTRES.getLocalizedMessage("store.editcertprofilenotauthorized", authenticationToken.toString(), id));
        }
    }

    @Override
    public boolean authorizedToProfileWithResource(
            final AuthenticationToken authenticationToken,
            final CertificateProfile profile,
            final boolean logging,
            final String... resources
    ) {
        // We need to check that admin also have rights to the passed in resources
        final List<String> rules = new ArrayList<>(Arrays.asList(resources));
        if (profile.isApplicableToAnyCA()) {
            if (resources.length != 1 || !StandardRules.CERTIFICATEPROFILEVIEW.resource().equals(resources[0])) {
                // If not just viewing, we require /ca/ access
                rules.add(StandardRules.CAACCESS.resource());
            }
        } else {
            // Check that admin is authorized to all CAids
            for (final Integer caId : profile.getAvailableCAs()) {
                rules.add(StandardRules.CAACCESS.resource() + caId);
            }
        }
        // Perform authorization check
        if (logging) {
            return authorizationSession.isAuthorized(authenticationToken, rules.toArray(new String[0]));
        }
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, rules.toArray(new String[0]));
    }
    
    @Override
    public byte[] getProfileAsXml(
            final AuthenticationToken authenticationToken,
            final int profileId
    ) throws CertificateProfileDoesNotExistException, AuthorizationDeniedException {
        final CertificateProfile profile = getCertificateProfile(profileId);
        if (profile == null) {
            throw new CertificateProfileDoesNotExistException("Could not find certificate profile with ID '" + profileId + "' in the database.");
        }
        if(!authorizedToProfileWithResource(authenticationToken, profile, true, StandardRules.CERTIFICATEPROFILEVIEW.resource())) {
            throw new AuthorizationDeniedException("User " + authenticationToken.toString() + " was not authorized to view certificate profile with id " + profileId);
        }
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(); XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(profile.saveData());
            encoder.flush(); // try-with-resource closes it
            return baos.toByteArray();
        } catch (IOException e) {
            String msg = "Could not encode profile with ID " + profileId + " to XML: " + e.getMessage();
            LOG.debug(msg, e);
            throw new IllegalStateException(msg, e);
        }
    }

    // Logs a session event preserving constants:
    // ModuleTypes.CERTIFICATEPROFILE - The module where the operation took place.
    // ServiceTypes.CORE - The service(application) that performed the operation.
    private void logSessionEvent(
            final EventType eventType,
            final EventStatus eventStatus,
            final AuthenticationToken authenticationToken,
            final SecurityEventProperties securityEventProperties) {
        logSession.log(
                eventType, eventStatus,
                ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                authenticationToken.toString(),
                null,null, null,
                securityEventProperties.toMap()
        );
    }
}
