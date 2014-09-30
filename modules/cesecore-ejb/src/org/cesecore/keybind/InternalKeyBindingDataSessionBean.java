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
package org.cesecore.keybind;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.QueryResultWrapper;

/**
 * @see org.cesecore.keybind.InternalKeyBindingDataSessionLocal
 * @version $Id$
 */
@Stateless  //(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalKeyBindingDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalKeyBindingDataSessionBean implements InternalKeyBindingDataSessionLocal {

    private static final Logger log = Logger.getLogger(InternalKeyBindingDataSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();
    private static final Random rnd = new SecureRandom();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    // Myself needs to be looked up in postConstruct
    @Resource
    private SessionContext sessionContext;
    private InternalKeyBindingDataSessionLocal keyBindSession;

    @PostConstruct
    public void postConstruct() {
        // We lookup the reference to our-self in PostConstruct, since we cannot inject this.
        // We can not inject ourself, JBoss will not start then therefore we use this to get a reference to this session bean
        // to call readData we want to do it on the real bean in order to get
        // the transaction setting (REQUIRED) which creates a new transaction if one was not running (required to read LOBs in PostgreSQL)
        keyBindSession = sessionContext.getBusinessObject(InternalKeyBindingDataSessionLocal.class);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void flushCache() {
        InternalKeyBindingCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed "+InternalKeyBindingCache.class.getSimpleName());
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBinding getInternalKeyBinding(final int id) {
        // 1. Check (new) InternalKeyBindingCache if it is time to sync-up with database
        if (InternalKeyBindingCache.INSTANCE.shouldCheckForUpdates(id)) {
            if (log.isDebugEnabled()) {
                log.debug("Object with ID " + id + " will be checked for updates.");
            }
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache
            final InternalKeyBindingData internalKeyBindingData = keyBindSession.readData(id);
            if (internalKeyBindingData==null) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested object did not exist in database and will be purged from cache if present: " + id);
                }
                // Ensure that it is removed from cache
                InternalKeyBindingCache.INSTANCE.removeEntry(id);
            } else {
                final int digest = internalKeyBindingData.getProtectString(0).hashCode();
                final String type = internalKeyBindingData.getKeyBindingType();
                final String name = internalKeyBindingData.getName();
                final InternalKeyBindingStatus status = internalKeyBindingData.getStatusEnum();
                final String certificateId = internalKeyBindingData.getCertificateId();
                final int cryptoTokenId = internalKeyBindingData.getCryptoTokenId();
                final String keyPairAlias = internalKeyBindingData.getKeyPairAlias();
                final LinkedHashMap<Object,Object> dataMapToLoad = internalKeyBindingData.getDataMap();
                // Create new token and store it in the cache.
                final InternalKeyBinding internalKeyBinding = InternalKeyBindingFactory.INSTANCE.create(type, id, name, status, certificateId, cryptoTokenId, keyPairAlias, dataMapToLoad);
                InternalKeyBindingCache.INSTANCE.updateWith(id, digest, name, internalKeyBinding);
            }
            // 3. The cache compares the database data with what is in the cache
            // 4. If database is different from cache, replace it in the cache (while trying to keep activation)
        }
        // 5. Get InternalKeyBinding from cache (or null) and be merry
        return  InternalKeyBindingCache.INSTANCE.getEntry(id);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public InternalKeyBinding getInternalKeyBindingForEdit(final int id) {
        final InternalKeyBinding internalKeyBinding = getInternalKeyBinding(id);
        if (internalKeyBinding == null) {
            return null;
        } else {
            // 6. Create and return a clone (so clients don't mess with the cached object)
            final InternalKeyBinding internalKeyBindingClone = InternalKeyBindingFactory.INSTANCE.create(internalKeyBinding.getImplementationAlias(),
                    id, internalKeyBinding.getName(), internalKeyBinding.getStatus(), internalKeyBinding.getCertificateId(),
                    internalKeyBinding.getCryptoTokenId(), internalKeyBinding.getKeyPairAlias(), internalKeyBinding.getDataMapToPersist());
            return internalKeyBindingClone;
        }
    }

    @Override
    public int mergeInternalKeyBinding(InternalKeyBinding internalKeyBinding) throws InternalKeyBindingNameInUseException {
        if (log.isDebugEnabled()) {
            log.debug(">mergeInternalKeyBinding " + internalKeyBinding.getName() + " " + internalKeyBinding.getClass().getName());
        }
        int internalKeyBindingId = internalKeyBinding.getId();
        final String name = internalKeyBinding.getName();
        final InternalKeyBindingStatus status = internalKeyBinding.getStatus();
        final String type = InternalKeyBindingFactory.INSTANCE.getTypeFromImplementation(internalKeyBinding);
        final String certificateId = internalKeyBinding.getCertificateId();
        final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        final String keyPairAlias = internalKeyBinding.getKeyPairAlias();
        final LinkedHashMap<Object,Object> dataMap = internalKeyBinding.getDataMapToPersist();
        // Allocate a new internalKeyBindingId if we create the InternalKeyBinding
        InternalKeyBindingData internalKeyBindingData = null;
        if (internalKeyBindingId == 0) {
            final List<Integer> allUsedIds = getIds(null);
            Integer allocatedId = null;
            for (int i=0; i<100; i++) {
                final int current = Integer.valueOf(rnd.nextInt());
                if (!allUsedIds.contains(current)) {
                    allocatedId = current;
                    break;
                }
            }
            if (allocatedId == null) {
                throw new RuntimeException("Failed to allocate a new internalKeyBindingId.");
            }
            internalKeyBindingId = allocatedId.intValue();
            // We need to replace this object with an object that has the correct ID if we are going to cache it later
            internalKeyBinding = InternalKeyBindingFactory.INSTANCE.create(type, internalKeyBindingId, name,
                    status, certificateId, cryptoTokenId, keyPairAlias, dataMap);
            if (log.isDebugEnabled()) {
                log.debug("Allocated a new internalKeyBindingId: " + internalKeyBindingId);
            }
        } else {
            // The one invoking the method has specified an id and expects the object to exist
            internalKeyBindingData = entityManager.find(InternalKeyBindingData.class, internalKeyBindingId);
        }
        if (internalKeyBindingData == null) {
            // The InternalKeyBinding does not exist in the database, before we add it we want to check that the name is not in use
            if (isNameUsed(name)) {
                if (log.isDebugEnabled()) {
                    log.debug("isNameUsed("+name+")");
                }
                throw new InternalKeyBindingNameInUseException(intres.getLocalizedMessage("internalkeybinding.nameisinuse", name));
            }
            internalKeyBindingData = new InternalKeyBindingData(internalKeyBindingId, name, status, type, certificateId, cryptoTokenId, keyPairAlias, dataMap);
        } else {
            if (!isNameUsedByIdOnly(internalKeyBindingData.getName(), internalKeyBindingId)) {
                if (log.isDebugEnabled()) {
                    log.debug("!isNameUsedByIdOnly("+name+", "+internalKeyBindingId+")");
                }
                throw new InternalKeyBindingNameInUseException(intres.getLocalizedMessage("internalkeybinding.nameisinuse", name));
            }
            // It might be the case that the calling transaction has already loaded a reference to this token
            // and hence we need to get the same one and perform updates on this object instead of trying to
            // merge a new object.
            internalKeyBindingData.setName(name);
            internalKeyBindingData.setStatusEnum(status);
            internalKeyBindingData.setKeyBindingType(type);
            internalKeyBindingData.setCertificateId(certificateId);
            internalKeyBindingData.setCryptoTokenId(cryptoTokenId);
            internalKeyBindingData.setKeyPairAlias(keyPairAlias);
            internalKeyBindingData.setDataMap(dataMap);
            internalKeyBindingData.setLastUpdate(System.currentTimeMillis());
        }
        internalKeyBindingData = createOrUpdateData(internalKeyBindingData);
        // Update cache with provided token (it might be active and we like keeping things active)
        InternalKeyBindingCache.INSTANCE.updateWith(internalKeyBindingId, internalKeyBindingData.getProtectString(0).hashCode(), name, internalKeyBinding);
        if (log.isDebugEnabled()) {
            log.debug("<mergeInternalKeyBinding " + internalKeyBinding.getName());
        }
        return internalKeyBindingId;   // tokenId
    }

    @Override
    public boolean removeInternalKeyBinding(final int id) {
        final boolean ret = deleteData(id);
        InternalKeyBindingCache.INSTANCE.updateWith(id, 0, null, null);
        return ret;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String,Integer> getCachedNameToIdMap() {
        return InternalKeyBindingCache.INSTANCE.getNameToIdMap();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isNameUsed(final String name) {
        final Query query = entityManager.createQuery("SELECT a FROM InternalKeyBindingData a WHERE a.name=:name");
        query.setParameter("name", name);
        return !query.getResultList().isEmpty();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean isNameUsedByIdOnly(final String name, final int id) {
        final Query query = entityManager.createQuery("SELECT a FROM InternalKeyBindingData a WHERE a.name=:name");
        query.setParameter("name", name);
        @SuppressWarnings("unchecked")
        final List<InternalKeyBindingData> internalKeyBindingDatas = query.getResultList();
        for (final InternalKeyBindingData internalKeyBindingData: internalKeyBindingDatas) {
            if (internalKeyBindingData.getId() != id) {
                return false;
            }
        }
        return true;
    }

    //
    // Create Read Update Delete (CRUD) methods
    //

    @Override
    public InternalKeyBindingData readData(final int id) {
        final Query query = entityManager.createQuery("SELECT a FROM InternalKeyBindingData a WHERE a.id=:id");
        query.setParameter("id", id);
        return QueryResultWrapper.getSingleResult(query);
    }

    private InternalKeyBindingData createOrUpdateData(final InternalKeyBindingData data) {
        return entityManager.merge(data);
    }

    private boolean deleteData(final int id) {
        final Query query = entityManager.createQuery("DELETE FROM InternalKeyBindingData a WHERE a.id=:id");
        query.setParameter("id", id);
        return query.executeUpdate() == 1;
    }

    @SuppressWarnings("unchecked")
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getIds(String keyBindingType) {
        if (keyBindingType == null) {
            return entityManager.createQuery("SELECT a.id FROM InternalKeyBindingData a").getResultList();
        } else {
            final Query query = entityManager.createQuery("SELECT a.id FROM InternalKeyBindingData a WHERE a.keyBindingType=:keyBindingType");
            query.setParameter("keyBindingType", keyBindingType);
            return query.getResultList();
        }
    }

}
