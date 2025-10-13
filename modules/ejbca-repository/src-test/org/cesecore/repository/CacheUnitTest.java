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

import org.cesecore.dto.TimedDto;
import org.cesecore.repository.util.ReflectionUtil;
import org.cesecore.dto.DummyCertWithIndex;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.cesecore.repository.util.DtoUtil.getDummyCertWithIndex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CacheUnitTest {

    public static final long EXPIRATION_TIME_MS = 1000L;

    private Cache<DummyCertWithIndex, Long> cache;
    private Map<Long, TimedDto<DummyCertWithIndex>> idToTimedDtoMap;
    private Map<Integer, Long> indexToIdMap;
    private Map<Long, Integer> idToIndexMap;

    private DummyCertWithIndex cert1;
    private DummyCertWithIndex cert2;

    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        this.cache = new Cache(EXPIRATION_TIME_MS);
        this.idToTimedDtoMap = ReflectionUtil.getFieldValue(cache, "idToTimedDtoMap");
        this.indexToIdMap = ReflectionUtil.getFieldValue(cache, "indexToIdMap");
        this.idToIndexMap = ReflectionUtil.getFieldValue(cache, "idToIndexMap");
        this.cert1 = getDummyCertWithIndex(10L, "common-1", "cert-1", "author-1", 100);
        this.cert2 = getDummyCertWithIndex(20L, "common-2", "cert-2", "author-2", 200);
    }

    private void addCertToMaps(final DummyCertWithIndex cert) {
        final var timedDto = new TimedDto<>(cert);
        idToTimedDtoMap.put(cert.getId(), timedDto);
        final Integer key = Cache.getCacheKey(cert.commonName(), cert.name());
        indexToIdMap.put(key, cert.getId());
        idToIndexMap.put(cert.getId(), key);
    }

    private void assertContainsCert(final String name, final DummyCertWithIndex cert) {
        final var timedDto = idToTimedDtoMap.get(cert.getId());
        assertNotNull(name+" is missing", timedDto);
        assertEquals("Wrong cert", cert, timedDto.dto());
        final Integer key = Cache.getCacheKey(cert.commonName(), cert.name());
        assertEquals("Wrong id", cert.getId(), indexToIdMap.get(key));
        assertEquals("Wrong index", key, idToIndexMap.get(cert.getId()));
    }

    private void assertNotContainsCert(final String name, final DummyCertWithIndex cert) {
        final var timedDto = idToTimedDtoMap.get(cert.getId());
        final Integer key = Cache.getCacheKey(cert.indexValues());
        if (timedDto == null) {
            assertNull(indexToIdMap.get(key));
            assertNull(idToIndexMap.get(cert.getId()));
        }
        else {
            // The dto is present. Verify that it has expired.
            assertNull(name+" is not supposed to be there", cache.getNonExpiredDto(timedDto));
            // It has expired, but the cache maps should still contain the values
            assertEquals("Wrong id", cert.getId(), indexToIdMap.get(key));
            assertEquals("Wrong index", key, idToIndexMap.get(cert.getId()));
        }
    }

    private void assertEmptyCache() {
        assertTrue("The cache is expected to be empty", idToTimedDtoMap.isEmpty());
        assertTrue("The cache is expected to be empty", indexToIdMap.isEmpty());
        assertTrue("The cache is expected to be empty", idToIndexMap.isEmpty());
    }

    @Test
    public void testRemoveByIdNonSynchronized_emptyCache() {
        // Given

        // When
        final DummyCertWithIndex actual = cache.removeByIdNonSynchronized(cert1.getId());

        // Then
        assertNull("There is no Dto that can be removed", actual);
        assertNotContainsCert("cert1", cert1);
        assertNotContainsCert("cert2", cert2);
    }

    @Test
    public void testRemoveByIdNonSynchronized_existingId() {
        // Given
        addCertToMaps(cert1);
        addCertToMaps(cert2);

        // When
        final DummyCertWithIndex actual = cache.removeByIdNonSynchronized(cert2.getId());

        // Then
        assertEquals("cert2 should be removed", cert2, actual);
        assertContainsCert("cert1", cert1);
        assertNotContainsCert("cert2", cert2);
    }

    @Test
    public void testRemoveByIdNonSynchronized_nonExistingId_filledCache() {
        // Given
        addCertToMaps(cert1);

        // When
        final DummyCertWithIndex actual = cache.removeByIdNonSynchronized(cert2.getId());

        // Then
        assertNull("cert2 cannot be removed", actual);
        assertContainsCert("cert1", cert1);
        assertNotContainsCert("cert2", cert2);
    }

    @Test
    public void testAddNonSynchronized_emptyCache() {
        // Given

        // When
        final var added = cache.addNonSynchronized(cert1);

        // Then
        assertEquals(added, cert1);
        assertContainsCert("cert1", cert1);
        assertNotContainsCert("cert2", cert2);
    }

    @Test
    public void testAddNonSynchronized_nonEmptyCache() {
        // Given
        addCertToMaps(cert1);

        // When
        final var added = cache.addNonSynchronized(cert2);

        // Then
        assertEquals(added, cert2);
        assertContainsCert("cert1", cert1);
        assertContainsCert("cert2", cert2);
    }

    @Test
    public void testAddNonSynchronized_idAlreadyExists() {
        // Given
        cache.addNonSynchronized(cert1);

        // When
        final var cert1_modified = cert2.withId(cert1.getId());
        cache.addNonSynchronized(cert1_modified);

        // Then
        assertContainsCert("cert1_modified", cert1_modified);
        assertEquals("Wrong values. cert1 is overwritten", cert1_modified, cache.findById(cert1.getId()));
        assertEquals("Wrong index. cert1 is overwritten.",
                Cache.getCacheKey(cert1_modified.indexValues()),
                idToIndexMap.get(cert1.getId()));
        assertNull("Wrong index. cert1 is overwritten.",
                indexToIdMap.get(Cache.getCacheKey(cert1.indexValues())));
    }

    @Test
    public void testAddNonSynchronized_hasExpired() throws InterruptedException {
        // Given
        cache.addNonSynchronized(cert1);

        // When
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // Then
        assertNotContainsCert("cert1", cert1);
    }

    @Test
    public void testRemoveByIndexNonSynchronized_emptyCache() {
        // Given

        // When
        final var removed = cache.removeByIndexNonSynchronized(Cache.getCacheKey(cert1.indexValues()));

        // Then
        assertNull("There is no Dto that can be removed", removed);
    }

    @Test
    public void testRemoveByIndexNonSynchronized_removeExisting() {
        // Given
        cache.addNonSynchronized(cert1);

        // When
        final var removed = cache.removeByIndexNonSynchronized(Cache.getCacheKey(cert1.indexValues()));

        // Then
        assertEquals("Wrong values. cert1 is removed", cert1, removed);
        assertEmptyCache();
   }

    @Test
    public void testRemoveByIndexNonSynchronized_removeExpired() throws InterruptedException {
        // Given
        cache.addNonSynchronized(cert1);

        // When
        Thread.sleep(EXPIRATION_TIME_MS+1);
        final var removed = cache.removeByIndexNonSynchronized(Cache.getCacheKey(cert1.indexValues()));

        // Then
        assertNull("cert1 has expired", removed);
        assertEmptyCache();
    }

}
