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

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.profiles.Profile;
import org.cesecore.profiles.ProfileData;
import org.cesecore.profiles.ProfileDoesNotExistException;
import org.cesecore.profiles.ProfileSessionLocal;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
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
    private ApprovalProfileCacheBean approvalProfileCache;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private ProfileSessionLocal profileSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public int addApprovalProfile(AuthenticationToken admin, ApprovalProfile profile)
            throws ApprovalProfileExistsException, AuthorizationDeniedException {
        authorizedToEditProfiles(admin);
        final String name = profile.getProfileName();
        if (findByApprovalProfileName(name).isEmpty()) {
            int profileId = profileSession.addProfile(profile);
            approvalProfileCache.forceCacheExpiration();
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.add", name);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            return profileId;
        } else {
            final String msg = INTRES.getLocalizedMessage("profile.store.error.profile_with_name_exists", name);
            throw new ApprovalProfileExistsException(msg);
        }
    }
 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws AuthorizationDeniedException {
        authorizedToEditProfiles(admin);
        String name = profile.getProfileName();
        profileSession.changeProfile(profile);
        String msg = INTRES.getLocalizedMessage("approval.profile.store.edit", name);
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        //TODO: Include a diff in the changelog (profileData.getProfile().diff(profile);), but make sure to resolve all steps so that we don't
        //      output a ton of serialized garbage (see ECA-5276)
        logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                admin.toString(), null, null, null, details);
        approvalProfileCache.forceCacheExpiration();
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final ApprovalProfile profile) throws AuthorizationDeniedException {
        removeApprovalProfile(admin, profile.getProfileId());
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException {
        authorizedToEditProfiles(admin);
        ProfileData profileData = profileSession.findById(id);
        if(profileData == null) {
            throw new IllegalArgumentException("No profile with ID " + id + " could be found.");
        }
        profileSession.removeProfile(profileData);
        approvalProfileCache.forceCacheExpiration();
        String msg = INTRES.getLocalizedMessage("approval.profile.store.remove", profileData.getProfileName());
        Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                admin.toString(), null, null, null, details);
    } 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameApprovalProfile(final AuthenticationToken admin, final ApprovalProfile approvalProfile, final String newName)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        if (findByApprovalProfileName(newName).isEmpty()) {
            authorizedToEditProfiles(admin);
            String oldName = approvalProfile.getProfileName();
            try {
                profileSession.renameProfile(approvalProfile, newName);
            } catch (ProfileDoesNotExistException e) {
                throw new ApprovalProfileDoesNotExistException(e);
            }
            approvalProfileCache.forceCacheExpiration();
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.rename", oldName, newName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_RENAME, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);

        } else {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.error.profile_with_name_exists", newName);
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
            final String msg = INTRES.getLocalizedMessage("profile.store.error.profile_not_found", approvalProfile.getProfileName());
            throw new ApprovalProfileDoesNotExistException(msg);
        }
        profile = getApprovalProfile(origProfileId).clone();
        profile.setProfileName(newName);
        authorizedToEditProfiles(admin);
        if (findByApprovalProfileName(newName).isEmpty()) {
            profileSession.addProfile(profile);
            approvalProfileCache.forceCacheExpiration();
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.clone", approvalProfile.getProfileName(), newName);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);    
            logSession.log(EjbcaEventTypes.APPROVAL_PROFILE_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL_PROFILE, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
        } else {
            final String msg = INTRES.getLocalizedMessage("approval.profile.store.clone.error.profile.name.exists", newName);
            throw new ApprovalProfileExistsException(msg);
        }    
    }
   
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAuthorizedApprovalProfileIds(final AuthenticationToken admin) {
        return new ArrayList<>(getAllApprovalProfiles().keySet());
    }    

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ProfileData> findByApprovalProfileName(String profileName) {
        return profileSession.findByNameAndType(profileName, Profile.PROFILE_TYPE);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ProfileData> findAllProfiles() {
        return profileSession.findAllProfiles(ApprovalProfile.TYPE_NAME);
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
    
    
    private void authorizedToEditProfiles(final AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.APPROVALPROFILEEDIT.resource())) {
            final String msg = INTRES.getLocalizedMessage("store.editapprovalprofilenotauthorized", admin.toString());
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
    public ApprovalProfile getApprovalProfileForAction(final ApprovalRequestType action, final CAInfo cainfo, final CertificateProfile certProfile) {
        if (certProfile != null) {
            Integer approvalProfileId = certProfile.getApprovals().get(action);                 
            if(approvalProfileId != null) {
                ApprovalProfile profile = getApprovalProfile(approvalProfileId);        
                if (profile != null && profile.isApprovalRequired()) { 
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Approval required from Certificate Profile, approval profile name: "+profile.getProfileName());
                    }
                    return profile;
                }
            }
        }
        if (cainfo != null) {         
            Integer approvalProfileId = cainfo.getApprovals().get(action);
            if(approvalProfileId != null) {
                ApprovalProfile profile = getApprovalProfile(approvalProfileId);             
                if (profile != null && profile.isApprovalRequired()) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Approval required from CA "+cainfo.getName()+", approval profile name: "+profile.getProfileName());
                    }
                    return profile;
                }
            }
        }
        return null;
    }

}
