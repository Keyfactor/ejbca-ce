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
package org.ejbca.core.ejb.signer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
 * @see org.ejbca.core.ejb.signer.SignerDataSessionLocal
 * @version $Id$
 */
@Stateless  //(mappedName = JndiConstants.APP_JNDI_PREFIX + "SignerMappingDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SignerMappingDataSessionBean implements SignerMappingDataSessionLocal {

    private static final Logger log = Logger.getLogger(SignerMappingDataSessionBean.class);
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;

    @PostConstruct
    public void postConstruct() {
        //CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void flushCache() {
        SignerMappingCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed Signer cache.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public SignerMapping getSignerMapping(final int signerMappingId) {
        // 1. Check (new) CryptoTokenCache if it is time to sync-up with database
        if (SignerMappingCache.INSTANCE.shouldCheckForUpdates(signerMappingId)) {
            if (log.isDebugEnabled()) {
                log.debug("Signer with ID " + signerMappingId + " will be checked for updates.");
            }
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache
            final SignerMappingData signerMappingData = readSignerMappingData(signerMappingId);
            if (signerMappingData==null) {
                if (log.isDebugEnabled()) {
                    log.debug("Requested cryptoTokenId did not exist in database and will be purged from cache if present: " + signerMappingId);
                }
                // Ensure that it is removed from cache
                SignerMappingCache.INSTANCE.removeEntry(signerMappingId);
            } else {
                final int digest = signerMappingData.getProtectString(0).hashCode();
                final String type = signerMappingData.getSignerType();
                final String name = signerMappingData.getName();
                final SignerMappingStatus status = signerMappingData.getStatusEnum();
                final String certificateId = signerMappingData.getCertificateId();
                final int cryptoTokenId = signerMappingData.getCryptoTokenId();
                final String keyPairAlias = signerMappingData.getKeyPairAlias();
                final LinkedHashMap<Object,Object> dataMapToLoad = signerMappingData.getDataMap();
                // Create new token and store it in the cache.
                final SignerMapping signer = SignerMappingFactory.INSTANCE.createSignerMapping(type, signerMappingId, name, status, certificateId, cryptoTokenId, keyPairAlias, dataMapToLoad);
                SignerMappingCache.INSTANCE.updateWith(signerMappingId, digest, name, signer);
            }
            // 3. The cache compares the database data with what is in the cache
            // 4. If database is different from cache, replace it in the cache (while trying to keep activation)
            //    (Invokes org.cesecore.keys.token.SignerFactory.createSigner)
        }
        // 5. Get CryptoToken from cache (or null) and be merry
        return SignerMappingCache.INSTANCE.getEntry(signerMappingId);
    }

    @Override
    public int mergeSignerMapping(final SignerMapping signerMapping) throws SignerMappingNameInUseException {
        if (log.isDebugEnabled()) {
            log.debug(">addCryptoToken " + signerMapping.getName() + " " + signerMapping.getClass().getName());
        }
        final int signerMappingId = signerMapping.getId();
        final String name = signerMapping.getName();
        final SignerMappingStatus status = signerMapping.getStatus();
        final String type = SignerMappingFactory.INSTANCE.getTypeFromImplementation(signerMapping);
        final String certificateId = signerMapping.getCertificateId();
        final int cryptoTokenId = signerMapping.getCryptoTokenId();
        final String keyPairAlias = signerMapping.getKeyPairAlias();
        final LinkedHashMap<Object,Object> dataMap = signerMapping.getDataMapToPersist();
        SignerMappingData signerMappingData = entityManager.find(SignerMappingData.class, signerMappingId);
        if (signerMappingData == null) {
            // The cryptoToken does not exist in the database, before we add it we want to check that the name is not in use
            if (isSignerMappingNameUsed(name)) {
                throw new SignerMappingNameInUseException(intres.getLocalizedMessage("signermapping.nameisinuse", name));
            }
            signerMappingData = new SignerMappingData(signerMappingId, name, status, type, certificateId, cryptoTokenId, keyPairAlias, dataMap);
        } else {
            if (!isSignerMappingNameUsedByIdOnly(name, signerMappingId)) {
                throw new SignerMappingNameInUseException(intres.getLocalizedMessage("signermapping.nameisinuse", name));
            }
            // It might be the case that the calling transaction has already loaded a reference to this token
            // and hence we need to get the same one and perform updates on this object instead of trying to
            // merge a new object.
            signerMappingData.setName(name);
            signerMappingData.setStatusEnum(status);
            signerMappingData.setSignerType(type);
            signerMappingData.setCertificateId(certificateId);
            signerMappingData.setCryptoTokenId(cryptoTokenId);
            signerMappingData.setKeyPairAlias(keyPairAlias);
            signerMappingData.setDataMap(dataMap);
            signerMappingData.setLastUpdate(System.currentTimeMillis());
        }
        signerMappingData = createOrUpdateSignerMappingData(signerMappingData);
        // Update cache with provided token (it might be active and we like keeping things active)
        SignerMappingCache.INSTANCE.updateWith(signerMappingId, signerMappingData.getProtectString(0).hashCode(), name, signerMapping);
        if (log.isDebugEnabled()) {
            log.debug("<addCryptoToken " + signerMapping.getName());
        }
        return signerMappingId;   // tokenId
    }

    @Override
    public void removeSignerMapping(final int signerMappingId) {
        deleteSignerMappingData(signerMappingId);
        SignerMappingCache.INSTANCE.updateWith(signerMappingId, 0, null, null);
    }
    
    @Override
    public Map<String,Integer> getCachedNameToIdMap() {
        return SignerMappingCache.INSTANCE.getNameToIdMap();
    }
    
    @Override
    public boolean isSignerMappingNameUsed(final String signerMappingName) {
        final Query query = entityManager.createQuery("SELECT a FROM SignerMappingData a WHERE a.name=:signerMappingName");
        query.setParameter("signerMappingName", signerMappingName);
        return !query.getResultList().isEmpty();
    }

    @Override
    public boolean isSignerMappingNameUsedByIdOnly(final String signerMappingName, final int signerMappingId) {
        final Query query = entityManager.createQuery("SELECT a FROM SignerMappingData a WHERE a.name=:signerMappingName");
        query.setParameter("signerMappingName", signerMappingName);
        List<SignerMappingData> signerMappingDatas = query.getResultList();
        if (signerMappingDatas.size() != 1) {
            return false;
        }
        for (SignerMappingData signerMappingData: signerMappingDatas) {
            if (signerMappingData.getId() != signerMappingId) {
                return false;
            }
        }
        return true;
    }

    //
    // Create Read Update Delete (CRUD) methods
    //

    private SignerMappingData readSignerMappingData(final int signerMappingId) {
        final Query query = entityManager.createQuery("SELECT a FROM SignerMappingData a WHERE a.id=:id");
        query.setParameter("id", signerMappingId);
        return QueryResultWrapper.getSingleResult(query);
    }

    private SignerMappingData createOrUpdateSignerMappingData(final SignerMappingData data) {
        return entityManager.merge(data);
    }

    private boolean deleteSignerMappingData(final int signerMappingId) {
        final Query query = entityManager.createQuery("DELETE FROM SignerMappingData a WHERE a.id=:id");
        query.setParameter("id", signerMappingId);
        return query.executeUpdate() == 1;
    }

    @SuppressWarnings("unchecked")
    @Override
    public List<Integer> getSignerMappingIds() {
        return entityManager.createQuery("SELECT a.id FROM SignerMappingData a").getResultList();
    }

}
