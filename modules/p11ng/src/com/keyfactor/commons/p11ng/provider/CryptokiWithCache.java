/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package com.keyfactor.commons.p11ng.provider;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.log4j.Logger;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.LongRef;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

/** 
 * Implementation of {@link CryptokiFacade} with caching, dispatching calls to another {@link CryptokiFacade} upon
 * cache misses.
 */
class CryptokiWithCache implements CryptokiFacade {
    private class AttributeKey {
        public final long objectRef;
        public final long ckaType;

        public AttributeKey(final long objectRef, final long ckaType) {
            this.objectRef = objectRef;
            this.ckaType = ckaType;
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(objectRef) + Objects.hashCode(ckaType);
        }

        @Override
        public boolean equals(final Object o) {
            if (o.getClass() != AttributeKey.class) {
                return false;
            }
            final AttributeKey attributeKey = (AttributeKey) o;
            return objectRef == attributeKey.objectRef && ckaType == attributeKey.ckaType;
        }

        @Override
        public String toString() {
            return String.format("(objectRef = %s, cka = %s)", objectRef, ckaType);
        }
    }

    private class CkaSet {
        public final Set<CKA> ckas;

        public CkaSet(final Set<CKA> ckas) {
            this.ckas = ckas;
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(ckas);
        }

        @Override
        public boolean equals(final Object o) {
            if (o.getClass() != CkaSet.class) {
                return false;
            }
            final CkaSet timestampedCka = (CkaSet) o;
            return timestampedCka.ckas.equals(this.ckas);
        }

        @Override
        public String toString() {
            return String.format(System.lineSeparator() +
                    "{" + System.lineSeparator() +
                    "    CKA => %s" + System.lineSeparator() +
                    "}" + System.lineSeparator(), ckas);
        }
    }

    private static final Logger log = Logger.getLogger(CryptokiWithCache.class);
    private final CryptokiFacade api;
    private final LinkedHashMap<AttributeKey, CKA> attributesCache = new LinkedHashMap<>();
    // In the object cache we want a timestamp so cache entries can expire for example in case a certificate object is changed
    private final LinkedHashMap<CkaSet, Pair<Long, List<Long>>> objectsCache = new LinkedHashMap<>();
    
    /**
     * 
     * @param api the underlying PKCS#11 API that will be called when there is a cache miss, unless using 
     * the method findObjectsInCache that will only look in the cache and not call underlying api.
     */
    CryptokiWithCache(final CryptokiFacade api) {
        this.api = api;
    }

    @Override
    public void clear() {
        attributesCache.clear();
        objectsCache.clear();
    }
    
    @Override
    public List<Long> findObjects(final long session, final CKA... ckas) {
        final CkaSet key = new CkaSet(Arrays.stream(ckas).collect(toSet()));
        final Pair<Long, List<Long>> objectRefsFromCache = objectsCache.get(key);
        if (objectRefsFromCache != null) {
            // Hard coded cache time of 2 minutes
            if ( !((System.currentTimeMillis() - (120 * 1000)) > objectRefsFromCache.getLeft()) ) {
                // Not expired return value
                return new ArrayList<>(objectRefsFromCache.getRight()); // Return copy
            }
        }
        // No entry in cache, or cache expired
        if (log.isTraceEnabled()) {
            log.trace(String.format("Cache miss, calling api.findObjects(session = %s, cka = %s)", session, Arrays.asList(ckas)));
        }
        final List<Long> objectRefsFromApi = api.findObjects(session, ckas);
        // It may be an empty list that we store in the cache as we cache "not found" as well
        objectsCache.put(key, Pair.of(System.currentTimeMillis(), objectRefsFromApi));
        // Return a copy to the cache for free use by the caller
        return new ArrayList<>(objectRefsFromApi);
    }

    @Override
    public Optional<List<Long>> findObjectsInCache(final long session, final CKA... ckas) {
        final Pair<Long, List<Long>> objectRefsFromCache = objectsCache.get(new CkaSet(Arrays.stream(ckas).collect(toSet())));
        if (log.isTraceEnabled()) {
            log.trace("Attempting to find objects in cache. Found " + (objectRefsFromCache == null ? "none" : objectRefsFromCache.getRight()));
            log.trace("Searching for objects with all these attributes set: " + Arrays.stream(ckas).map(cka -> cka.type).collect(toSet()));
            log.trace("Content of the objects cache: " + objectsCache);
        }
        // Return a copy to the cache for free use by the caller
        return objectRefsFromCache == null ? Optional.empty() : Optional.of(new ArrayList<>(objectRefsFromCache.getRight()));
    }

    @Override
    public void destroyObject(final long session, final long objectRef) {
        attributesCache.keySet().removeIf(attributeKey -> attributeKey.objectRef == objectRef);
        objectsCache.values().forEach(objectRefs -> objectRefs.getRight().remove(objectRef));
        api.destroyObject(session, objectRef);
    }

    @Override
    public CKA getAttributeValue(final long session, final long objectRef, final long ckaType) {
        final CKA attributeFromCache = attributesCache.get(new AttributeKey(objectRef, ckaType));
        if (attributeFromCache != null) {
            return attributeFromCache;
        } else {
            if (log.isTraceEnabled()) {
                log.trace(String.format("Cache miss, calling api.GetAttributeValue(session = %s, cka = %s)", session, ckaType));
            }
            final CKA attributeFromApi = api.getAttributeValue(session, objectRef, ckaType);
            attributesCache.put(new AttributeKey(objectRef, ckaType), attributeFromApi);
            return attributeFromApi;
        }        
    }

    @Override
    public void generateKeyPair(final long session, final CKM mechanism, final CKA[] publicKeyTemplate,
                                final CKA[] privateKeyTemplate, final LongRef publicKey, final LongRef privateKey) {
        api.generateKeyPair(session, mechanism, publicKeyTemplate, privateKeyTemplate, publicKey, privateKey);
        objectsCache.clear();
    }

    @Override
    public void generateKey(long session, CKM mechanism, CKA[] secretKeyTemplate, LongRef secretKey) {
        api.generateKey(session, mechanism, secretKeyTemplate, secretKey);
        objectsCache.clear();
    }

    @Override
    public long createObject(final long session, final CKA... template) {
        final long objectHandle = api.createObject(session, template);
        objectsCache.clear();
        return objectHandle;
    }

    @Override
    public void logout(final long session) {
        api.logout(session);
        attributesCache.clear();
        objectsCache.clear();
    }
}
