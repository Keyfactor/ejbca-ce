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
import org.ejbca.core.ejb.profiles.ProfileData;
import org.ejbca.core.model.approval.ApprovalProfile;

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
            if (ProfileData.findByApprovalProfileName(entityManager, name) == null) {
                entityManager.persist(new ProfileData(Integer.valueOf(id), name, profile));
                flushProfileCache();
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
        if (ProfileData.findByIdAndType(entityManager, Integer.valueOf(id), ApprovalProfile.TYPE) == null) {
            foundfree = true;
        }
        return foundfree;
    }
    
    
    
    
    
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeApprovalProfile(final AuthenticationToken admin, final String name, final ApprovalProfile profile)
            throws AuthorizationDeniedException {

        final ProfileData pdl = ProfileData.findByNameAndType(entityManager, name, ApprovalProfile.TYPE);
        if (pdl == null) {
            LOG.info(INTRES.getLocalizedMessage("store.erroreditapprovalprofile", name) + ". No such profile was found");
        } else {
            authorizedToEditProfile(admin, profile, pdl.getId());

            // Do the actual change
            pdl.setProfile(profile);
            LOG.info(INTRES.getLocalizedMessage("store.editedapprovalprofile", name));

        }
        flushProfileCache();
    }
    
    
    
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        final ProfileData pdl = ProfileData.findByNameAndType(entityManager, name, ApprovalProfile.TYPE);
        if (pdl == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist: " + name);
            }
        } else {
            authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

            entityManager.remove(pdl);
            flushProfileCache();
            LOG.info(INTRES.getLocalizedMessage("store.removedprofile", name));
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeApprovalProfile(final AuthenticationToken admin, final int id) throws AuthorizationDeniedException {
        final ProfileData pdl = ProfileData.findByIdAndType(entityManager, id, ApprovalProfile.TYPE);
        if (pdl == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Trying to remove an approval profile that does not exist. ID: " + id);
            }
        } else {
            authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

            final String name = pdl.getProfileName();
            entityManager.remove(pdl);
            flushProfileCache();
            LOG.info(INTRES.getLocalizedMessage("store.removedprofile", name));
        }
    } 
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameApprovalProfile(final AuthenticationToken admin, final String oldname, final String newname)
            throws ApprovalProfileExistsException, ApprovalProfileDoesNotExistException, AuthorizationDeniedException {
        if (ProfileData.findByNameAndType(entityManager, newname, ApprovalProfile.TYPE) == null) {
            final ProfileData pdl = ProfileData.findByNameAndType(entityManager, oldname, ApprovalProfile.TYPE);
            if (pdl == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorprofilenotexist", oldname);
                throw new ApprovalProfileDoesNotExistException(msg);
            } else {
                authorizedToEditProfile(admin, pdl.getProfile(), pdl.getId());

                pdl.setProfileName(newname);
                flushProfileCache();
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
            final ApprovalProfile p = getApprovalProfile(origProfileId);
            if (p == null) {
                final String msg = INTRES.getLocalizedMessage("store.errorprofilenotexist", orgname);
                LOG.info(msg);
                throw new ApprovalProfileDoesNotExistException(msg);
            }

            profile = p.clone();

            authorizedToEditProfile(admin, profile, origProfileId);

            if (ProfileData.findByNameAndType(entityManager, newname, ApprovalProfile.TYPE) == null) {
                entityManager.persist(new ProfileData(findFreeApprovalProfileId(), newname, profile));
                flushProfileCache();
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

    
    @Override
    public void flushProfileCache() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">flushProfileCache");
        }
        ApprovalProfileCache.INSTANCE.updateProfileCache(entityManager, true);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Flushed profile cache.");
        }
    } // flushProfileCache

    
    private int findFreeApprovalProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return ProfileData.findByIdAndType(entityManager, Integer.valueOf(i), ApprovalProfile.TYPE)==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    @Override
    public Map<Integer, ApprovalProfile> getAllApprovalProfiles() {
        return ApprovalProfileCache.INSTANCE.getProfileCache(entityManager);
    }

    @Override
    public Collection<ApprovalProfile> getApprovalProfilesList() {
        Map<Integer, ApprovalProfile> allProfiles = ApprovalProfileCache.INSTANCE.getProfileCache(entityManager);
        
        
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
        final ApprovalProfile aprofile = ApprovalProfileCache.INSTANCE.getProfileCache(entityManager).get(Integer.valueOf(id));
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
        final Integer id = ApprovalProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(name);
        if (id == null) {
            return null;
        } else {
            return getApprovalProfile(id);
        }
    }

    @Override
    public int getApprovalProfileId(String name) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfileId: " + name);
        }
        int returnval = 0;
        final Integer id = ApprovalProfileCache.INSTANCE.getNameIdMapCache(entityManager).get(name);
        if (id != null) {
            returnval = id.intValue();
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<getApprovalProfileId: " + name + "): " + returnval);
        }
        return returnval;
    }

    @Override
    public String getApprovalProfileName(int id) {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">getApprovalProfileName: " + id);
        }
        final String returnval = ApprovalProfileCache.INSTANCE.getIdNameMapCache(entityManager).get(Integer.valueOf(id));
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
        return ApprovalProfileCache.INSTANCE.getIdNameMapCache(entityManager);
    }
    
    
    private void authorizedToEditProfile(final AuthenticationToken admin, final ApprovalProfile profile, final int id) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.APPROVALPROFILEEDIT.resource())) {
            final String msg = INTRES.getLocalizedMessage("store.editapprovalprofilenotauthorized", admin.toString(), id);
            throw new AuthorizationDeniedException(msg);
        }
    }

}
