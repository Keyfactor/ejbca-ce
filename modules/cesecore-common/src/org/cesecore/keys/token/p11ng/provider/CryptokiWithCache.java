/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.token.p11ng.provider;

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

    private class TimestampedCkaSet {
        public final Set<CKA> ckas;
        public final long timestamp;

        public TimestampedCkaSet(final Set<CKA> ckas) {
            this.ckas = ckas;
            this.timestamp = System.currentTimeMillis();
        }

        boolean isExpired() {
            // Hard coded cache time of 2 minutes
            return (System.currentTimeMillis() - (120 * 1000)) > timestamp;
        }

        @Override
        public int hashCode() {
            return Objects.hashCode(ckas);
        }

        @Override
        public boolean equals(final Object o) {
            if (o.getClass() != TimestampedCkaSet.class) {
                return false;
            }
            final TimestampedCkaSet timestampedCka = (TimestampedCkaSet) o;
            return timestampedCka.ckas.equals(this.ckas);
        }

        @Override
        public String toString() {
            return String.format(System.lineSeparator() +
                    "{" + System.lineSeparator() +
                    "    timestamp => %s" + System.lineSeparator() +
                    "    CKA => %s" + System.lineSeparator() +
                    "}" + System.lineSeparator(), timestamp, ckas);
        }
    }

    private static final Logger log = Logger.getLogger(CryptokiWithCache.class);
    private final CryptokiFacade api;
    private final LinkedHashMap<AttributeKey, CKA> attributesCache = new LinkedHashMap<>();
    private final LinkedHashMap<TimestampedCkaSet, List<Long>> objectsCache = new LinkedHashMap<>();
    
    /**
     * 
     * @param api the underlying PKCS#11 API that will be called when there is a cache miss, unless using 
     * the method findObjectsInCache that will only look in the cache and not call underlying api.
     */
    CryptokiWithCache(final CryptokiFacade api) {
        this.api = api;
    }

    @Override
    public List<Long> findObjects(final long session, final CKA... ckas) {
        final Optional<List<Long>> objectRefsFromCache = findObjectsInCache(session, ckas);
        if (objectRefsFromCache.isPresent()) {
            return new ArrayList<>(objectRefsFromCache.get());
        } else {
            if (log.isTraceEnabled()) {
                log.trace(String.format("Cache miss, calling api.findObjects(session = %s, cka = %s)", session, Arrays.asList(ckas)));
            }
            final List<Long> objectRefsFromApi = api.findObjects(session, ckas);
            objectsCache.put(new TimestampedCkaSet(Arrays.stream(ckas).collect(toSet())), objectRefsFromApi);
            // Return a copy to the cache can be modified while these search results are used
            return new ArrayList<>(objectRefsFromApi);
        }
    }

    @Override
    public Optional<List<Long>> findObjectsInCache(final long session, final CKA... ckas) {
        objectsCache.keySet().removeIf(timestampedCkaList -> timestampedCkaList.isExpired());
        final List<Long> objectRefsFromCache = objectsCache.get(new TimestampedCkaSet(Arrays.stream(ckas).collect(toSet())));
        if (log.isTraceEnabled()) {
            log.trace("Attempting to find objects in cache. Found " + objectRefsFromCache);
            log.trace("Searching for objects with all these attributes set: " + Arrays.stream(ckas).map(cka -> cka.type).collect(toSet()));
            log.trace("Content of the objects cache: " + objectsCache);
        }
        // Return a copy to the cache can be modified while these search results are used
        return objectRefsFromCache == null ? Optional.empty() : Optional.of(new ArrayList<>(objectRefsFromCache));
    }

    @Override
    public void destroyObject(final long session, final long objectRef) {
        attributesCache.keySet().removeIf(attributeKey -> attributeKey.objectRef == objectRef);
        objectsCache.values().forEach(objectRefs -> objectRefs.remove(objectRef));
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
