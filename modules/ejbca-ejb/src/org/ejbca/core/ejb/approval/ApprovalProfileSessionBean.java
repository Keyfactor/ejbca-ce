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
package org.ejbca.core.ejb.approval;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.profiles.ProfileData;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfileBase;

/**
 * Keeps track of the approval profiles
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalProfileSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalProfileSessionBean implements ApprovalProfileSessionLocal, ApprovalProfileSessionRemote {
    
    private static final Logger LOG = Logger.getLogger(ApprovalProfileSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @EJB
    private AccessControlSessionLocal accessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private ApprovalProfileCacheBean approvalProfileCache;
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public int addApprovalProfile(AuthenticationToken admin, ApprovalProfile profile) throws ApprovalProfileExistsException, AuthorizationDeniedException {
        final int id = findFreeApprovalProfileId();
        authorizedToEditProfile(admin, id);
        String name = profile.getProfileName();
        if (isFreeApprovalProfileId(id)) {
            if (findByApprovalProfileName(name).isEmpty()) {
                profile.setProfileId(id);
                entityManager.persist(new ProfileData(Integer.valueOf(id), profile));
                approvalProfileCache.forceCacheExpiration();
                final String msg = INTRES.getLocalizedMessage("approval.profile.store.add", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
                return id;
            } else {
                final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.name.exists", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_ADD, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
                throw new ApprovalProfileExistsException(msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.id.exists", id);
            throw new ApprovalProfileExistsException(msg);
        }
    }
    
    private boolean isFreeApprovalProfileId(final int id) {
        boolean foundfree = false;
        if (findById(id) == null) {
            foundfree = true;
        }
        return foundfree;
    }
     
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile)
            throws AuthorizationDeniedException {
        String name = profile.getProfileName();
        Integer profileId = profile.getProfileId();
        if(profileId == null) {
            throw new IllegalArgumentException("ApprovalProfile did not contain a valid ID");
        }
        final ProfileData profileData = findById(profile.getProfileId());
        if (profileData == null) {
            String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.not.found", name);
            LOG.info(msg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_EDIT, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            authorizedToEditProfile(admin, profileData.getId());
            // Get the diff of what changed
            Map<Object, Object> diff = profileData.getProfile().diff(profile);
            // Do the actual change
            profileData.setProfile(profile);
            entityManager.merge(profileData);
            entityManager.flush();
            String msg = INTRES.getLocalizedMessage("approval.profile.store.edit", name);
            LOG.info(msg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);         
            //Note that steps are serialized, so output will not give better information than a diff. 
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        }
        approvalProfileCache.forceCacheExpiration();
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws AuthorizationDeniedException {
        final ProfileData profileData = findById(profile.getProfileId());
        if (profileData == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist: " + profile.getProfileName());
            }
        } else {
            authorizedToEditProfile(admin, profileData.getId());
            entityManager.remove(profileData);
            approvalProfileCache.forceCacheExpiration();
            String msg = INTRES.getLocalizedMessage("approval.profile.store.remove", profile.getProfileName()); 
            LOG.info(msg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException {
        final ProfileData profileData = findById(id);
        if (profileData == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist. ID: " + id);
            }
        } else {
            authorizedToEditProfile(admin, profileData.getId());
            final String name = profileData.getProfileName();
            entityManager.remove(profileData);
            approvalProfileCache.forceCacheExpiration();
            String msg = INTRES.getLocalizedMessage("approval.profile.store.remove", name); 
            LOG.info(msg);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        }
    } 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameApprovalProfile(final AuthenticationToken admin, final ApprovalProfile approvalProfile, final String newName)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        if (findByNameAndType(newName, ApprovalProfile.TYPE_NAME).isEmpty()) {
            final ProfileData profileData = findById(approvalProfile.getProfileId());
            if (profileData == null) {
                final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.not.found", approvalProfile.getProfileName());
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);    
                logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_RENAME, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
                throw new ApprovalProfileDoesNotExistException(msg);
            } else {
                authorizedToEditProfile(admin, profileData.getId());
                String oldName = approvalProfile.getProfileName();
                profileData.setProfileName(newName);
                approvalProfileCache.forceCacheExpiration();
                final String msg = INTRES.getLocalizedMessage("approval.profile.store.rename", oldName, newName);
                LOG.info(msg);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);    
                logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_RENAME, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.name.exists", newName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_RENAME, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            throw new ApprovalProfileExistsException(msg);
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneApprovalProfile(final AuthenticationToken admin, final ApprovalProfile approvalProfile, final String newName)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        ApprovalProfile profile = null;

        final Integer origProfileId = approvalProfile.getProfileId();
        if (origProfileId == null) {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile.not.found", approvalProfile.getProfileName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_CLONE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            throw new ApprovalProfileDoesNotExistException(msg);
        }
        profile = getApprovalProfile(origProfileId).clone();
        profile.setProfileName(newName);
        authorizedToEditProfile(admin, origProfileId);
        if (findByNameAndType(newName, ApprovalProfile.TYPE_NAME).isEmpty()) {
            entityManager.persist(new ProfileData(findFreeApprovalProfileId(), profile));
            approvalProfileCache.forceCacheExpiration();
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.clone", approvalProfile.getProfileName(), newName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_CLONE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            LOG.info(msg);
        } else {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.clone.error.profile.name.exists", newName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_CLONE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            throw new ApprovalProfileExistsException(msg);
        }
      
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ProfileData findById(int id) {
        return entityManager.find(ProfileData.class, id);
    }
   
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAuthorizedApprovalProfileIds(final AuthenticationToken admin) {
        return new ArrayList<>(getAllApprovalProfiles().keySet());
    }    
    
    private int findFreeApprovalProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return findById(i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ProfileData> findByApprovalProfileName(String profileName) {
        TypedQuery<ProfileData> query = entityManager
                .createQuery("SELECT a FROM ProfileData a WHERE a.profileName=:profileName AND a.profileType=:profileType", ProfileData.class);
        query.setParameter("profileName", profileName);
        query.setParameter("profileType", ApprovalProfileBase.PROFILE_TYPE);
        return query.getResultList();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ProfileData> findByNameAndType(final String name, final String type) {
        TypedQuery<ProfileData> query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileName=:name AND a.profileType=:profileType", ProfileData.class);
        query.setParameter("name", name);
        query.setParameter("profileType", type);
        return query.getResultList();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ProfileData> findAllApprovalProfiles() {
        TypedQuery<ProfileData> query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileType=:profileType", ProfileData.class);
        query.setParameter("profileType", ApprovalProfile.TYPE_NAME);
        List<ProfileData> ret = query.getResultList();
        return ret;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, ApprovalProfile> getAllApprovalProfiles() {
        return approvalProfileCache.getProfileCache();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<ApprovalProfile> getApprovalProfilesList() {
        Map<Integer, ApprovalProfile> allProfiles = approvalProfileCache.getProfileCache();    
        ArrayList<ApprovalProfile> profiles = new ArrayList<>();
        Set<Entry<Integer, ApprovalProfile>> entries = allProfiles.entrySet();
        for (Entry<Integer, ApprovalProfile> entry : entries) {
            ApprovalProfile profile = entry.getValue();
            profiles.add(profile);
        }
        return profiles;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ApprovalProfile getApprovalProfile(int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfile(" + id + ")");
        }
        ApprovalProfile returnval = null;
        final ApprovalProfile aprofile = approvalProfileCache.getProfileCache().get(Integer.valueOf(id));
        // We need to clone the profile, otherwise the cache contents will be modifiable from the outside
        if (aprofile != null) {
            returnval = aprofile.clone();
        }
   
        
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getApprovalProfile(" + id + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getApprovalProfileName(int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfileName: " + id);
        }
        final String returnval = approvalProfileCache.getIdNameMapCache().get(Integer.valueOf(id));
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getApprovalProfileName: " + id + "): " + returnval);
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getApprovalProfileIdToNameMap() {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getApprovalProfileIdToNameMap");
        }
        return approvalProfileCache.getIdNameMapCache();
    }
    
    
    private void authorizedToEditProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.APPROVALPROFILEEDIT.resource())) {
            final String msg = INTRES.getLocalizedMessage("store.editapprovalprofilenotauthorized", admin.toString(), id);
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void forceProfileCacheRebuild() {
       approvalProfileCache.updateProfileCache(true);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ApprovalProfile getApprovalProfileForAction(final int action, final CAInfo cainfo, final CertificateProfile certProfile) {
        if (certProfile != null) {
            int approvalProfileId = certProfile.getApprovalProfileID();
            if (approvalProfileId != -1) {
                ApprovalProfile profile = getApprovalProfile(approvalProfileId);        
                if (certProfile.getApprovalSettings().contains(Integer.valueOf(action)) && profile.isApprovalRequired()) {
                    return profile;
                }
            }
        }
        if (cainfo != null) {
            int approvalProfileId = cainfo.getApprovalProfile();
            if (approvalProfileId != -1) {
                ApprovalProfile profile = getApprovalProfile(approvalProfileId);
                if (cainfo.getApprovalSettings().contains(Integer.valueOf(action)) && profile.isApprovalRequired()) {
                    return profile;
                }
            }
        }
        return null;
    }

}
