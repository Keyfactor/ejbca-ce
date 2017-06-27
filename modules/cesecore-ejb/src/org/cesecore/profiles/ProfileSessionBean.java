/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.profiles;

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.ProfileID;

/**
 * 
 * Basic CRUD bean for ProfileData objects
 * 
 * @version $Id$
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ProfileSessionBean implements ProfileSessionLocal {

    private static final Logger log = Logger.getLogger(ProfileSessionBean.class);
    
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    
       
    @Override
    public int addProfile(final Profile profile) {
        final int id = findFreeProfileId();
        if (isFreeProfileId(id)) {
            entityManager.persist(new ProfileData(Integer.valueOf(id), profile));
            return id;
        } else {
            final String msg = INTRES.getLocalizedMessage("profile.store.error.profile.id.exists", id);
            throw new IllegalStateException(msg);
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ProfileData findById(int id) {
        return entityManager.find(ProfileData.class, id);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeProfile( final Profile profile) {
        Integer profileId = profile.getProfileId();
        if (profileId == null) {
            throw new IllegalArgumentException("Profile did not contain a valid ID");
        }
        String name = profile.getProfileName();

        final ProfileData profileData = findById(profile.getProfileId());
        if (profileData == null) {
            String msg = INTRES.getLocalizedMessage("profile.store.error.profile.not.found", name);
            log.info(msg);
        } else {         
            // Get the diff of what changed
            // Do the actual change
            profileData.setProfile(profile);
            entityManager.merge(profileData);
            entityManager.flush();
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeProfile(final ProfileData profileData) {
        entityManager.remove(profileData);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameProfile(final Profile profile, final String newName) throws ProfileDoesNotExistException {
        final ProfileData profileData = findById(profile.getProfileId());
        if (profileData == null) {
            final String msg = INTRES.getLocalizedMessage("profile.store.error.profile.not.found", profile.getProfileName());
            throw new ProfileDoesNotExistException(msg);
        } else {
            // This changes the name in the database column
            profileData.setProfileName(newName);
            // This changes the name in the profile XML data
            Profile original = profileData.getProfile();
            original.setProfileName(newName);
            profileData.setProfile(original);
        }
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
    public List<ProfileData> findAllProfiles(final String profileType) {
        TypedQuery<ProfileData> query = entityManager.createQuery("SELECT a FROM ProfileData a WHERE a.profileType=:profileType", ProfileData.class);
        query.setParameter("profileType", profileType);
        List<ProfileData> ret = query.getResultList();
        return ret;
    }
    
    private boolean isFreeProfileId(final int id) {
        boolean foundfree = false;
        if (findById(id) == null) {
            foundfree = true;
        }
        return foundfree;
    }
    
    private int findFreeProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return findById(i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }
    
    
    
}
