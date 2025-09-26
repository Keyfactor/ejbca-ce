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

import org.cesecore.dto.DummyCertWithIndex;
import org.cesecore.dto.DummyCertWithIndexBean;
import org.cesecore.repository.exception.RecordIdAlreadyExistsException;
import org.cesecore.repository.exception.RecordIdDoesNotExistException;
import org.cesecore.repository.exception.RecordIndexAlreadyExistsException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import static org.cesecore.repository.util.DtoUtil.getDummyCertWithIndex;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class CachedDatabaseUnitTest {

    private Database<DummyCertWithIndex, Long, DummyCertWithIndexBean> database;
    private Cache<DummyCertWithIndex, Long> cache;
    private CachedDatabase<DummyCertWithIndex, Long, DummyCertWithIndexBean> cachedDatabase;

    private DummyCertWithIndex cert1;
    private DummyCertWithIndex cert2;
    private DummyCertWithIndex cert1_modified;

    @Before
    public void setUp() {
        database = Mockito.mock(Database.class);
        cache = Mockito.mock(Cache.class);
        cachedDatabase = new CachedDatabase<>(database, cache);
        cert1 = getDummyCertWithIndex(1L, "common-name-1", "name-1", "author-1", 1);
        cert2 = getDummyCertWithIndex(2L, "common-name-2", "name-2", "author-2", 2);
        cert1_modified = cert2.withId(cert1.getId());
    }

    @Test
    public void testAddNonSynchronized_idAndIndexFree() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addNonSynchronized(cert1)).thenReturn(cert1);
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        cachedDatabase.addNonSynchronized(cert1);

        // Then
        verify(database, times(1)).addNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testAddNonSynchronized_idAlreadyInCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addNonSynchronized(cert1)).thenReturn(cert1);
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(cert1_modified);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        cachedDatabase.addNonSynchronized(cert1);

        // Then
        verify(database, times(1)).addNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testAddNonSynchronized_indexAlreadyInCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addNonSynchronized(cert1)).thenReturn(cert1);
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(cert1);

        // When
        cachedDatabase.addNonSynchronized(cert1);

        // Then
        verify(database, times(1)).addNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test(expected = RecordIdAlreadyExistsException.class)
    public void testAddNonSynchronized_idAlreadyInDatabaseButNotInCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addNonSynchronized(cert1)).thenThrow(new RecordIdAlreadyExistsException("some message"));
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        cachedDatabase.addNonSynchronized(cert1);

        // Then
        verify(database, times(1)).addNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test(expected = RecordIndexAlreadyExistsException.class)
    public void testAddNonSynchronized_indexAlreadyInDatabaseButNotInCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addNonSynchronized(cert1)).thenThrow(new RecordIndexAlreadyExistsException("some message"));
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        cachedDatabase.addNonSynchronized(cert1);

        // Then
        verify(database, times(1)).addNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testFindByIdNonSynchronized_noMatchFromDataBase_noMatchFromCache() {
        // Given
        when(database.findByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.findByIdNonSynchronized(cert1.id())).thenReturn(null);

        // When
        final var actual = cachedDatabase.findByIdNonSynchronized(cert1.id());

        // Then
        assertNull(actual);
        verify(database, times(1)).findByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).findByIdNonSynchronized(cert1.id());
    }

    @Test
    public void testFindByIdNonSynchronized_matchFromDatabase_noMatchFromCache() {
        // Given
        when(database.findByIdNonSynchronized(cert1.id())).thenReturn(cert1);
        when(cache.findByIdNonSynchronized(cert1.id())).thenReturn(null);

        // When
        final var actual = cachedDatabase.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).findByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).findByIdNonSynchronized(cert1.id());
    }

    @Test
    public void testFindByIdNonSynchronized_noMatchFromDatabase_matchFromCache() {
        // Given
        when(database.findByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.findByIdNonSynchronized(cert1.id())).thenReturn(cert1);

        // When
        final var actual = cachedDatabase.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(0)).findByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).findByIdNonSynchronized(cert1.id());
    }

    @Test
    public void testFindByIdNonSynchronized_matchFromDatabase_matchFromCache_equalMatches() {
        // Given
        when(database.findByIdNonSynchronized(cert1.id())).thenReturn(cert1);
        when(cache.findByIdNonSynchronized(cert1.id())).thenReturn(cert1);

        // When
        final var actual = cachedDatabase.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(0)).findByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).findByIdNonSynchronized(cert1.id());
    }

    @Test
    public void testFindByIdNonSynchronized_matchFromDatabase_matchFromCache_nonEqualMatches() {
        // Given
        when(database.findByIdNonSynchronized(cert1.id())).thenReturn(cert1);
        when(cache.findByIdNonSynchronized(cert1.id())).thenReturn(cert1_modified);

        // When
        final var actual = cachedDatabase.findByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1_modified, actual);
        verify(database, times(0)).findByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).findByIdNonSynchronized(cert1.id());
    }

    @Test
    public void testFindByIndexNonSynchronized_noMatchFromDataBase_noMatchFromCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.findByIndexNonSynchronized(cert1.indexValues())).thenReturn(null);
        when(cache.findByIndexNonSynchronized(key)).thenReturn(null);

        // When
        final var actual = cachedDatabase.findByIndexNonSynchronized(cert1.indexValues());

        // Then
        assertNull(actual);
        verify(database, times(1)).findByIndexNonSynchronized(cert1.indexValues());
        verify(cache,    times(1)).findByIndexNonSynchronized(key);
    }

    @Test
    public void testFindByIndexNonSynchronized_matchFromDatabase_noMatchFromCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.findByIndexNonSynchronized(cert1.indexValues())).thenReturn(cert1);
        when(cache.findByIndexNonSynchronized(key)).thenReturn(null);

        // When
        final var actual = cachedDatabase.findByIndexNonSynchronized(cert1.indexValues());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).findByIndexNonSynchronized(cert1.indexValues());
        verify(cache,    times(1)).findByIndexNonSynchronized(key);
    }

    @Test
    public void testFindByIndexNonSynchronized_noMatchFromDatabase_matchFromCache() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.findByIndexNonSynchronized(cert1.indexValues())).thenReturn(null);
        when(cache.findByIndexNonSynchronized(key)).thenReturn(cert1);

        // When
        final var actual = cachedDatabase.findByIndexNonSynchronized(cert1.indexValues());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(0)).findByIndexNonSynchronized(cert1.indexValues());
        verify(cache,    times(1)).findByIndexNonSynchronized(key);
    }

    @Test
    public void testFindByIndexNonSynchronized_matchFromDatabase_matchFromCache_equalMatches() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.findByIndexNonSynchronized(cert1.indexValues())).thenReturn(cert1);
        when(cache.findByIndexNonSynchronized(key)).thenReturn(cert1);

        // When
        final var actual = cachedDatabase.findByIndexNonSynchronized(cert1.indexValues());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(0)).findByIndexNonSynchronized(cert1.indexValues());
        verify(cache,    times(1)).findByIndexNonSynchronized(key);
    }

    @Test
    public void testFindByIndexNonSynchronized_matchFromDatabase_matchFromCache_nonEqualMatches() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.findByIndexNonSynchronized(cert1.indexValues())).thenReturn(cert1);
        when(cache.findByIndexNonSynchronized(key)).thenReturn(cert1_modified);

        // When
        final var actual = cachedDatabase.findByIndexNonSynchronized(cert1.indexValues());

        // Then
        assertEquals(cert1_modified, actual);
        verify(database, times(0)).findByIndexNonSynchronized(cert1.indexValues());
        verify(cache,    times(1)).findByIndexNonSynchronized(key);
    }

    @Test
    public void testFindAllNonSynchronized() {
        // Given
        final var expected = List.of(cert1, cert2);
        when(database.findAllNonSynchronized()).thenReturn(expected);

        // When
        final var actual = cachedDatabase.findAllNonSynchronized();

        // Then
        assertEquals(expected, actual);
        verify(database, times(1)).findAllNonSynchronized();
        verify(cache,    times(0)).findAllNonSynchronized();
    }

    @Test
    public void testAddOrUpdateNonSynchronized_databaseAccepts_certWithoutId() {
        // Given
        final var cert1_withoutId = cert1.withId(null);
        final var key = Cache.getCacheKey(cert1_withoutId.indexValues());
        when(database.addOrUpdateNonSynchronized(cert1_withoutId)).thenReturn(cert1);
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        final var actual = cachedDatabase.addOrUpdateNonSynchronized(cert1_withoutId);

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).addOrUpdateNonSynchronized(cert1_withoutId);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testAddOrUpdateNonSynchronized_databaseAccepts_certWithId() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addOrUpdateNonSynchronized(cert1)).thenReturn(cert1);
        when(cache.removeByIdNonSynchronized(cert1.id())).thenReturn(null);
        when(cache.removeByIndexNonSynchronized(key)).thenReturn(null);

        // When
        final var actual = cachedDatabase.addOrUpdateNonSynchronized(cert1);

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).addOrUpdateNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test( expected = RecordIdAlreadyExistsException.class )
    public void testAddOrUpdateNonSynchronized_idAlreadyExists() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addOrUpdateNonSynchronized(cert1)).thenThrow(new RecordIdAlreadyExistsException("some message"));

        // When
        final var actual = cachedDatabase.addOrUpdateNonSynchronized(cert1);

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).addOrUpdateNonSynchronized(cert1);
        verify(cache,    times(0)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(0)).removeByIndexNonSynchronized(key);
    }

    @Test( expected = RecordIndexAlreadyExistsException.class )
    public void testAddOrUpdateNonSynchronized_indexAlreadyExists() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        when(database.addOrUpdateNonSynchronized(cert1)).thenThrow(new RecordIndexAlreadyExistsException("some message"));

        // When
        final var actual = cachedDatabase.addOrUpdateNonSynchronized(cert1);

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).addOrUpdateNonSynchronized(cert1);
        verify(cache,    times(0)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(0)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testUpdateNonSynchronized_certFound() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());

        // When
        cachedDatabase.updateNonSynchronized(cert1);

        // Then
        verify(database, times(1)).updateNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test(expected = RecordIdDoesNotExistException.class)
    public void testUpdateNonSynchronized_certNotFound() {
        // Given
        final var key = Cache.getCacheKey(cert1.indexValues());
        doThrow(new RecordIdDoesNotExistException("some message")).when(database).updateNonSynchronized(cert1);

        // When
        cachedDatabase.updateNonSynchronized(cert1);

        // Then
        verify(database, times(1)).updateNonSynchronized(cert1);
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIndexNonSynchronized(key);
    }

    @Test
    public void testRemoveByIdNonSynchronized_certNotFound() {
        // Given

        // When
        final var actual = cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertNull(actual);
        verify(database, times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());

    }

    @Test
    public void testRemoveByIdNonSynchronized_certFound() {
        // Given
        when(database.removeByIdNonSynchronized(cert1.id())).thenReturn(cert1);

        // When
        final var actual = cachedDatabase.removeByIdNonSynchronized(cert1.id());

        // Then
        assertEquals(cert1, actual);
        verify(database, times(1)).removeByIdNonSynchronized(cert1.id());
        verify(cache,    times(1)).removeByIdNonSynchronized(cert1.id());

    }

}
