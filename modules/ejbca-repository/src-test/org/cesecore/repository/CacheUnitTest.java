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

package org.cesecore.repository;

import org.cesecore.repository.dto.TimedDto;
import org.cesecore.repository.util.ReflectionUtil;
import org.ejbca.dto.DummyCert;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.cesecore.repository.CachedDatabaseUnitTest.getDummyCert;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CacheUnitTest {

    public static final long EXPIRATION_TIME_MS = 1000L;

    private Cache<DummyCert, Long> cache;
    private Map<Long, TimedDto<DummyCert>> idToTimedDtoMap;
    private Map<String, Long> indexToIdMap;
    private Map<Long, String> idToIndexMap;

    private DummyCert cert1;
    private DummyCert cert2;

    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        this.cache = new Cache(EXPIRATION_TIME_MS);
        this.idToTimedDtoMap = ReflectionUtil.getFieldValue(cache, "idToTimedDtoMap");
        this.indexToIdMap = ReflectionUtil.getFieldValue(cache, "indexToIdMap");
        this.idToIndexMap = ReflectionUtil.getFieldValue(cache, "idToIndexMap");
        this.cert1 = getDummyCert(10L, "cert-1", "author-1", 100);
        this.cert2 = getDummyCert(20L, "cert-2", "author-2", 200);
    }

    private void assertMapsContains(final DummyCert cert) {
        assertNotNull(cert);
        assertNotNull("The cache is expected to have an entity with id " + cert.id(), idToTimedDtoMap.get(cert.id()));
        assertEquals("The cache is expected to contain the entity " + cert, cert, idToTimedDtoMap.get(cert.id()).dto());
        if (cert.index() != null) {
            assertEquals("The cache is missing the id "+cert.id(), cert.id(), indexToIdMap.get(cert.index()));
            assertEquals("The cache is missing the index "+cert.index(), cert.index(), idToIndexMap.get(cert.id()));
        }
    }

    private void assertMapsDoesNotContain(final DummyCert cert) {
        assertNotNull(cert);
        assertNull("The cache contains the unexpected id "+cert.id(), idToTimedDtoMap.get(cert.id()));
        assertNull("The cache contains the unexpected id "+cert.id(), idToIndexMap.get(cert.id()));
        assertNull("The cache contains the unexpected index "+cert.index(), indexToIdMap.get(cert.index()));
    }

    private void assertCacheContains(final DummyCert cert) {
        assertNotNull(cert);
        assertEquals("The cache contains wrong value for id " + cert.id(), cert, cache.findById(cert.id()));
        if (cert.index() != null) {
            assertEquals("The cache contains wrong value for index " + cert.index(), cert, cache.findByIndex(cert.index()));
        }
    }

    private void assertCacheDoesNotContain(final DummyCert cert) {
        assertNotNull(cert);
        assertNull("The cache contains the unexpected id " + cert.id(), cache.findById(cert.id()));
        assertNull("The cache contains the unexpected index " + cert.index(), cache.findByIndex(cert.index()));
    }

    @Test
    public void testAddNonSynchronized() {
        // Given

        // When
        cache.add(cert1);

        // Then
        assertMapsContains(cert1);
        assertCacheContains(cert1);
    }

    @Test
    public void testAddNonSynchronized_expired() throws InterruptedException {
        // Given
        cache.add(cert1);

        // When
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // Then
        assertMapsContains(cert1);
        assertCacheDoesNotContain(cert1);
    }

    @Test
    public void testIsExpired_true() {
        assertTrue(cache.isExpired(System.currentTimeMillis()-EXPIRATION_TIME_MS-1));
    }

    @Test
    public void testIsExpired_false() {
        assertFalse(cache.isExpired(System.currentTimeMillis()-EXPIRATION_TIME_MS+1));
    }

    @Test
    public void testGetNonExpiredDto_null() {
        assertNull(cache.getNonExpiredDto(null));
    }

    @Test
    public void testGetNonExpiredDto_expired() throws InterruptedException {
        final var timedDto = new TimedDto<>(cert1);
        Thread.sleep(EXPIRATION_TIME_MS+1);
        assertNull("The entity " + timedDto.dto() + " has expired and shall not be found in the cache", cache.getNonExpiredDto(timedDto));
    }

    @Test
    public void testGetNonExpiredDto_nonExpired() {
        final var timedDto = new TimedDto<>(getDummyCert(10L, "some cert", "some author", 20));
        assertNotNull("The entity " + timedDto.dto() + " has not expired and shall be found in the cache", cache.getNonExpiredDto(timedDto));
    }

    @Test
    public void testRemoveNonSynchronized_idDoesExist() {
        // Given
        cache.add(cert1);

        // When
        cache.removeByIdNonSynchronized(cert1.id());

        // Then
        assertMapsDoesNotContain(cert1);
    }

    @Test
    public void testRemoveNonSynchronized_idDoesNotExist() {
        // Given
        cache.add(cert1);

        // When
        cache.removeByIdNonSynchronized(cert1.id());

        // Then
        assertMapsDoesNotContain(cert1);
    }

    @Test
    public void testClearNonSynchronized() {
        // Given
        cache.add(cert1);
        assertMapsContains(cert1);

        // When
        cache.clearNonSynchronized();

        // Then
        assertTrue("The cache is expected to be empty", idToTimedDtoMap.isEmpty());
        assertTrue("The cache is expected to be empty", indexToIdMap.isEmpty());
        assertTrue("The cache is expected to be empty", idToIndexMap.isEmpty());
    }

    @Test
    public void testClearExpired() throws InterruptedException {
        // Given
        cache.add(cert1);
        Thread.sleep(EXPIRATION_TIME_MS+1);
        cache.add(cert2);
        assertMapsContains(cert1);
        assertMapsContains(cert2);

        // When
        cache.clearExpired();

        // Then
        assertMapsDoesNotContain(cert1);
        assertMapsContains(cert2);
    }

}
