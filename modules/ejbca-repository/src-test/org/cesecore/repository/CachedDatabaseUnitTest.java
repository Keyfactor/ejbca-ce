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

import org.cesecore.repository.mock.EntityManagerMock;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.ejbca.dto.DummyCert;
import org.ejbca.dto.DummyCertBean;
import org.ejbca.dto.DummyCertConverter;
import org.ejbca.dto.DummyCertRecord;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class CachedDatabaseUnitTest {

    protected static final long EXPIRATION_TIME_MS = 1000L;

    private EntityManagerMock<DummyCert> entityManagerMock;
    private DummyCertConverter certConverter = new DummyCertConverter();
    private CachedDatabase<DummyCert, Long, DummyCertBean> cachedDatabase;
    private Database<DummyCert, Long, DummyCertBean> database;
    private Cache<DummyCert, Long> cache;
    private DummyCert cert1;
    private DummyCert cert2;
    private AtomicLong nextId;

    private int compare(Object o1, Object o2) {
        DummyCertBean cert1 = (DummyCertBean) o1;
        if (o2 instanceof Long) {
            Long id = (Long) o2;
            return Objects.equals(cert1.getId(), id) ? 0 : 1;
        }
        else {
            DummyCertBean cert2 = (DummyCertBean) o2;
            return Objects.equals(cert1.getId(), cert2.getId()) ? cert1.getName().compareTo(cert2.getName()) : -1;
        }
    }

    static DummyCert getDummyCert(Long id, String name, String author, int years) {
        return new DummyCertRecord(id, name, Collections.unmodifiableMap(new HashMap<>() {{
            put("author", author);
            put("years", years);
        }}));
    }

    static DummyCertBean getCertBean(Long id, String name, String author, int years) {
        return new DummyCertConverter().toBean(getDummyCert(id, name, author, years));
    }

    @Before
    public void setUp() throws NoSuchFieldException, IllegalAccessException {
        nextId = new AtomicLong(1L);
        entityManagerMock = new EntityManagerMock<>((o1, o2) -> compare(o1, o2));
        database = new Database<>(entityManagerMock,
                DummyCertBean.class,
                certConverter,
                "name",
                () -> nextId.getAndIncrement());
        cache = new Cache<>(EXPIRATION_TIME_MS);
        cachedDatabase = new CachedDatabase<>(database, cache);
        cert1 = getDummyCert(1L, "name-1", "author-1", 1);
        cert2 = getDummyCert(2L, "name-2", "author-2", 2);
    }

    @Test
    public void testAddNonSynchronized_emptyDb() {
        // Given

        // When
        cachedDatabase.add(cert1);

        // Then
        Assert.assertEquals(1, entityManagerMock.getTypedQueryMock().getResultList().size());
        assertEquals(certConverter.toBean(cert1), entityManagerMock.getTypedQueryMock().getResultList().get(0));
        assertEquals(cert1, cache.findById(cert1.id()));
    }

    @Test(expected = RecordIdAlreadyExistsException.class)
    public void testAddNonSynchronized_dbAlreadyContainsBean() {
        // Given
        final DummyCertBean certBean = certConverter.toBean(cert1);
        entityManagerMock.getTypedQueryMock()
                .getResultList()
                .add(certBean);

        // When
        cachedDatabase.add(cert1);
    }

    @Test
    public void testAddNonSynchronized_cacheContainsExpiredRecord() throws InterruptedException {
        // Given
        cache.add(cert1);
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // When
        cachedDatabase.add(cert1);

        // Then
        Assert.assertEquals(1, entityManagerMock.getTypedQueryMock().getResultList().size());
        DummyCertBean bean1 = certConverter.toBean(cert1);
        Assert.assertEquals(bean1, entityManagerMock.getTypedQueryMock().getResultList().get(0));
    }

    @Test
    public void testFindByIdNonSynchronized_emptyDbAndCache() {
        // Given

        // When
        final var actual = cachedDatabase.findById(cert1.id());

        // Then
        assertNull(actual);
    }

    @Test
    public void testFindByIdNonSynchronized_dbContainsId() {
        // Given
        entityManagerMock.getTypedQueryMock().getResultList().add(certConverter.toBean(cert1));

        // When
        final var actual = cachedDatabase.findById(cert1.id());

        // Then
        assertEquals(cert1, actual);
    }

    @Test
    public void testFindByIdNonSynchronized_cacheContainsId() {
        // Given
        cache.add(cert1);

        // When
        final var actual = cachedDatabase.findById(cert1.id());

        // Then
        assertEquals(cert1, actual);
    }

    @Test
    public void testFindByIdNonSynchronized_cacheContainsExpiredId() throws InterruptedException {
        // Given
        cache.add(cert1);
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // When
        final var actual = cachedDatabase.findById(cert1.id());

        // Then
        assertNull(actual);
    }

    @Test
    public void testFindByIdNonSynchronized_cacheAndDbContainsDifferentRecordsForSameId() throws InterruptedException {
        // Given
        DummyCert dbRecord = getDummyCert(1L, "db-name-1", "db-author-1", 1);
        DummyCertBean dbBean = certConverter.toBean(dbRecord);
        entityManagerMock.getTypedQueryMock().getResultList().add(dbBean);
        DummyCert cacheRecord = getDummyCert(dbRecord.id(), "cache-name-100", "cache-author-100", 100);
        cache.add(cacheRecord);

        // When
        final var actual = cachedDatabase.findById(dbRecord.id());

        // Then
        assertNotNull(actual);
        assertEquals(cacheRecord, actual);
    }

    @Test
    public void testFindByIdNonSynchronized_cacheAndDbContainsDifferentRecordsForSameIdButCacheHasExpired() throws InterruptedException {
        // Given
        DummyCert dbRecord = getDummyCert(1L, "db-name-1", "db-author-1", 1);
        DummyCertBean dbBean = certConverter.toBean(dbRecord);
        entityManagerMock.getTypedQueryMock().getResultList().add(dbBean);
        DummyCert cacheRecord = getDummyCert(dbRecord.id(), "cache-name-100", "cache-author-100", 100);
        cache.add(cacheRecord);
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // When
        final var actual = cachedDatabase.findById(dbRecord.id());

        // Then
        assertNotNull(actual);
        assertEquals(dbRecord, actual);
    }

    @Test
    public void testFindByIndexNonSynchronized_dbContainsIndex() {
        // Given
        entityManagerMock.getTypedQueryMock().getResultList().add(certConverter.toBean(cert1));
    
        // When
        final var actual = cachedDatabase.findByIndex(cert1.index());
    
        // Then
        assertNotNull(actual);
        assertEquals(cert1, actual);
    }

    @Test
    public void testFindByIndexNonSynchronized_cacheContainsExpiredIndex() throws InterruptedException {
        // Given
        cache.add(cert1);
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // When
        final var actual = cachedDatabase.findByIndex(cert1.index());

        // Then
        assertNull(actual);
    }

    @Test
    public void testFindByIndexNonSynchronized_cacheAndDbContainsDifferentRecordsForSameIndexButCacheHasExpired() throws InterruptedException {
        // Given
        DummyCert dbRecord = getDummyCert(1L, "db-name-1", "db-author-1", 1);
        DummyCertBean dbBean = certConverter.toBean(dbRecord);
        entityManagerMock.getTypedQueryMock().getResultList().add(dbBean);
        DummyCert cacheRecord = getDummyCert(100L, dbRecord.index(), "cache-author-100", 100);
        cache.add(cacheRecord);
        Thread.sleep(EXPIRATION_TIME_MS+1);

        // When
        final var actual = cachedDatabase.findByIndex(dbRecord.index());

        // Then
        assertNotNull(actual);
        assertEquals(dbRecord, actual);
    }

    @Test
    public void removeByIdNonSynchronized_idExistsInDatabaseAndCache() {
        // Given
        database.add(cert1);
        assertEquals(cert1, database.findByIdNonSynchronized(cert1.id()));
        cache.add(cert1);
        assertEquals(cert1, cache.findByIdNonSynchronized(cert1.id()));

        // When
        var actual = cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertNull(database.findByIdNonSynchronized(cert1.id()));
        assertNull(cache.findByIdNonSynchronized(cert1.id()));
    }

    @Test
    public void removeByIdNonSynchronized_idExistsInDatabaseButNotInCache() {
        // Given
        database.add(cert1);
        assertEquals(cert1, database.findByIdNonSynchronized(cert1.id()));

        // When
        cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertNull(database.findByIdNonSynchronized(cert1.id()));
        assertNull(cache.findByIdNonSynchronized(cert1.id()));
    }

    @Test
    public void removeByIdNonSynchronized_idExistsInCacheButNotInDatabase() {
        // Given
        cache.add(cert1);
        assertEquals(cert1, cache.findByIdNonSynchronized(cert1.id()));

        // When
        cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertNull(database.findByIdNonSynchronized(cert1.id()));
        assertNull(cache.findByIdNonSynchronized(cert1.id()));
    }

    @Test
    public void removeByIdNonSynchronized_idDoesntExistsInCacheNorInDatabase() {
        // Given

        // When
        cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertNull(database.findByIdNonSynchronized(cert1.id()));
        assertNull(cache.findByIdNonSynchronized(cert1.id()));
    }

}
