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
import java.util.Iterator;
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
import javax.persistence.Query;

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
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;
import org.cesecore.util.QueryResultWrapper;
import org.ejbca.core.ejb.profiles.ProfileData;
import org.ejbca.core.model.approval.ApprovalProfile;

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

    @Override
    public int addApprovalProfile(AuthenticationToken admin, String name, ApprovalProfile profile) throws ApprovalProfileExistsException, AuthorizationDeniedException {
        return addApprovalProfile(admin, findFreeApprovalProfileId(), name, profile);
    }
    
    private int addApprovalProfile(final AuthenticationToken admin, final int id, final String name, final ApprovalProfile profile)
            throws ApprovalProfileExistsException, AuthorizationDeniedException {

        authorizedToEditProfile(admin, profile, id);

        if (isFreeApprovalProfileId(id)) {
            if (findByApprovalProfileName(name) == null) {
                entityManager.persist(new ProfileData(Integer.valueOf(id), name, profile));
                approvalProfileCache.forceCacheExpiration();
                final String msg = INTRES.getLocalizedMessage("store.addedprofile", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                logSession.log(EventTypes.CERTPROFILE_CREATION, EventStatus.SUCCESS, ModuleTypes.CERTIFICATEPROFILE, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
                return id;
            } else {
                final String msg = INTRES.getLocalizedMessage("store.errorprofileexists", name);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                throw new ApprovalProfileExistsException(msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorprofileexists", id);
            throw new ApprovalProfileExistsException(msg);
        }
    }

    private boolean isFreeApprovalProfileId(final int id) {
        boolean foundfree = false;
        if (findByIdAndType(Integer.valueOf(id), ApprovalProfile.TYPE) == null) {
            foundfree = true;
        }
        return foundfree;
    }
     
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeApprovalProfile(final AuthenticationToken admin, final String name, final ApprovalProfile profile)
            throws AuthorizationDeniedException {

        final ProfileData pdl = findByNameAndType( name, ApprovalProfile.TYPE);
        if (pdl == null) {
            LOG.info(INTRES.getLocalizedMessage("store.erroreditapprovalprofile", name) + ". No such profile was found");
        } else {
            authorizedToEditProfile(admin, profile, pdl.getId());

            // Do the actual change
            pdl.setProfile(profile);
            LOG.info(INTRES.getLocalizedMessage("store.editedapprovalprofile", name));

        }
        approvalProfileCache.forceCacheExpiration();
    }
    
    
    
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        final ProfileData pdl = findByNameAndType(name, ApprovalProfile.TYPE);
        if (pdl == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist: " + name);
            }
        } else {
            authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

            entityManager.remove(pdl);
            approvalProfileCache.forceCacheExpiration();
            LOG.info(INTRES.getLocalizedMessage("store.removedprofile", name));
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException {
        final ProfileData pdl = findByIdAndType(id, ApprovalProfile.TYPE);
        if (pdl == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist. ID: " + id);
            }
        } else {
            authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

            final String name = pdl.getProfileName();
            entityManager.remove(pdl);
            approvalProfileCache.forceCacheExpiration();
            LOG.info(INTRES.getLocalizedMessage("store.removedprofile", name));
        }
    } 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameApprovalProfile(final AuthenticationToken admin, final String oldname, final String newname)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        if (findByNameAndType(newname, ApprovalProfile.TYPE) == null) {
            final ProfileData pdl = findByNameAndType(oldname, ApprovalProfile.TYPE);
            if (pdl == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorprofilenotexist", oldname);
                throw new ApprovalProfileDoesNotExistException(msg);
            } else {
                authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

                pdl.setProfileName(newname);
                approvalProfileCache.forceCacheExpiration();
                final String msg = INTRES.getLocalizedMessage("store.renamedprofile", oldname, newname);
                LOG.info(msg);
            }
        } else {
            final String msg = INTRES.getLocalizedMessage("store.errorprofileexists", newname);
            throw new ApprovalProfileExistsException(msg);
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneApprovalProfile(final AuthenticationToken admin, final String orgname, final String newname)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        ApprovalProfile profile = null;

        try {
            final int origProfileId = getApprovalProfileId(orgname);
            if (origProfileId == 0) {
                final String msg = INTRES.getLocalizedMessage("store.errorprofilenotexist", orgname);
                LOG.info(msg);
                throw new ApprovalProfileDoesNotExistException(msg);
            }
            final ApprovalProfile p = getApprovalProfile(origProfileId);

            profile = p.clone();

            authorizedToEditProfile(admin, profile, origProfileId);

            if (findByNameAndType(newname, ApprovalProfile.TYPE) == null) {
                entityManager.persist(new ProfileData(findFreeApprovalProfileId(), newname, profile));
                approvalProfileCache.forceCacheExpiration();
                final String msg = INTRES.getLocalizedMessage("store.addedprofilewithtempl", newname, orgname);
                LOG.info(msg);
            } else {
                final String msg = INTRES.getLocalizedMessage("store.erroraddprofilewithtempl", newname, orgname);
                throw new ApprovalProfileExistsException(msg);
            }
        } catch (CloneNotSupportedException f) {
            // If this happens it's a programming error. Throw an exception!
            throw new IllegalStateException(f);
        }
    }
    
    @Override
    public ProfileData findByIdAndType(final int id, final String type) {
        Query query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.id=:id AND a.profileType=:profileType");
        query.setParameter("id", id);
        query.setParameter("profileType", ApprovalProfile.TYPE);
        return (ProfileData) QueryResultWrapper.getSingleResult(query);
    } 
    
    @Override
    public ProfileData findById(int id) {
        return entityManager.find(ProfileData.class, id);
    }

    
    
    
    @Override
    public List<Integer> getAuthorizedApprovalProfileIds(final AuthenticationToken admin) {
        // TODO Implement correctly
        ArrayList<Integer> ret = new ArrayList<Integer>();
        Map<Integer, ApprovalProfile> allProfiles = getAllApprovalProfiles();
        Set<Integer> ids = allProfiles.keySet();
        for(Integer id : ids) {
            ret.add(id);
        }
        return ret;
    }    
    
    private int findFreeApprovalProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return findByIdAndType(Integer.valueOf(i), ApprovalProfile.TYPE)==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @Override
    public ProfileData findByApprovalProfileName(String profileName) {
        Query query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileName=:profileName AND a.profileType=:profileType");
        query.setParameter("profileName", profileName);
        query.setParameter("profileType", ApprovalProfile.TYPE);
        return (ProfileData) QueryResultWrapper.getSingleResult(query);
    }
    
    @Override
    public ProfileData findByNameAndType(final String name, final String type) {
        Query query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileName=:name AND a.profileType=:profileType");
        query.setParameter("name", name);
        query.setParameter("profileType", ApprovalProfile.TYPE);
        return (ProfileData) QueryResultWrapper.getSingleResult(query);
    }
    
    @Override
    public List<ProfileData> findAllApprovalProfiles() {
        Query query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileType=:profileType");
        query.setParameter("profileType", ApprovalProfile.TYPE);
        @SuppressWarnings("unchecked")
        List<ProfileData> ret = query.getResultList();
        return ret;
    }
    
    @Override
    public Map<Integer, ApprovalProfile> getAllApprovalProfiles() {
        return approvalProfileCache.getProfileCache();
    }

    @Override
    public Collection<ApprovalProfile> getApprovalProfilesList() {
        Map<Integer, ApprovalProfile> allProfiles = approvalProfileCache.getProfileCache();
        
        
        ArrayList<ApprovalProfile> profiles = new ArrayList<ApprovalProfile>();
        Set<Entry<Integer, ApprovalProfile>> entries = allProfiles.entrySet();
        Iterator<Entry<Integer, ApprovalProfile>> itr = entries.iterator();
        while(itr.hasNext()) {
            Entry<Integer, ApprovalProfile> entry = itr.next();
            ApprovalProfile profile = entry.getValue();
            profiles.add(profile);
        }
        return profiles;
    }

    @Override
    public ApprovalProfile getApprovalProfile(int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfile(" + id + ")");
        }
        ApprovalProfile returnval = null;
        // We need to clone the profile, otherwise the cache contents will be modifiable from the outside
        final ApprovalProfile aprofile = approvalProfileCache.getProfileCache().get(Integer.valueOf(id));
        try {
            if (aprofile != null) {
                returnval = aprofile.clone();
            }
        } catch (CloneNotSupportedException e) {
            LOG.error("Should never happen: ", e);
            throw new IllegalStateException(e);
        }
        
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getApprovalProfile(" + id + "): " + (returnval == null ? "null" : "not null"));
        }
        return returnval;
    }

    @Override
    public ApprovalProfile getApprovalProfile(String name) {
        final Integer id = approvalProfileCache.getNameIdMapCache().get(name);
        if (id == null) {
            return null;
        } else {
            return getApprovalProfile(id);
        }
    }

    @Override
    public int getApprovalProfileId(String name) throws ApprovalProfileDoesNotExistException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfileId: " + name);
        }
        
        final Integer id = approvalProfileCache.getNameIdMapCache().get(name);
        if (id != null) {
            final int returnval = id.intValue();
            if (LOG.isTraceEnabled()) {
                LOG.trace("<getApprovalProfileId: " + name + "): " + returnval);
            }
            return returnval;
        }
        throw new ApprovalProfileDoesNotExistException("Approval profile '" + name + "' does not exist");
    }

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

    @Override
    public Map<Integer, String> getApprovalProfileIdToNameMap() {
        if (LOG.isTraceEnabled()) {
            LOG.trace("><getApprovalProfileIdToNameMap");
        }
        return approvalProfileCache.getIdNameMapCache();
    }
    
    
    private void authorizedToEditProfile(final AuthenticationToken admin, final ApprovalProfile profile, final int id) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.APPROVALPROFILEEDIT.resource())) {
            final String msg = INTRES.getLocalizedMessage("store.editapprovalprofilenotauthorized", admin.toString(), id);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public void forceProfileCacheExpire() {
       approvalProfileCache.forceCacheExpiration();
    }
    
    @Override
    public void forceProfileCacheRebuild() {
       approvalProfileCache.updateProfileCache(true);
    }

}
